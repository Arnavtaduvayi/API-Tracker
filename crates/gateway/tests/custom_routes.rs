//! Custom-origin route lifecycle, end to end (ADR 0021, TEST_PLAN §3a).
//!
//! The property under test is the one the final independent audit found
//! missing: a custom-origin route registered through a supported user action
//! must actually become FORWARDABLE. Before this, `RouteState::set_mac_key`
//! had no callers anywhere in the tree, so every custom route answered 503
//! forever — and the 503 text told the user to unlock their vault, which
//! installed nothing.
//!
//! These tests drive the real control channel against a real `Service`, then
//! send real HTTP through the listener to a synthetic upstream, so a
//! regression that breaks the wiring (rather than the unit) is caught.

mod common;

use common::*;
use std::io::{Read, Write};
use std::time::Duration;

use api_tracker_core::secret::SecretBytes;
use api_tracker_gateway::control::{self, Request, Response};
use api_tracker_gateway::routes::{self, RouteTarget, Unforwardable};
use api_tracker_gateway::service::Service;

/// A distinctive, obviously-synthetic route key. Never a real secret.
fn route_key() -> SecretBytes {
    SecretBytes::new(vec![0xC5; 32])
}

#[cfg(unix)]
fn service_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

#[cfg(unix)]
fn push_route_key(data_dir: &std::path::Path, key: &SecretBytes) {
    assert!(
        control::push_route_key(data_dir, key),
        "the route verification key must install over the control channel"
    );
}

#[cfg(unix)]
fn status(data_dir: &std::path::Path) -> control::Status {
    let nonce = control::read_nonce(data_dir).unwrap();
    match control::send(
        data_dir,
        &Request::Status {
            nonce: nonce.to_string(),
        },
    )
    .unwrap()
    {
        Response::Status(s) => *s,
        other => panic!("expected status, got {other:?}"),
    }
}

/// The public origin used for MAC-verification tests. It is never dialed —
/// these tests assert what the route table RESOLVES to, not what a socket
/// reaches — but it must be a real public authority because the load-time
/// SSRF policy (correctly) refuses to resolve a loopback origin at all.
const CUSTOM_ORIGIN: &str = "myref.supabase.co";

/// Register a custom-origin route exactly as production stores one: the MAC
/// is computed with the real `route_mac`, so a change to the MAC's input set
/// breaks these tests rather than silently passing.
#[cfg(unix)]
fn register_custom_route(db: &std::path::Path, prefix: &str, provider: &str, key: &SecretBytes) {
    let conn = open_db(db);
    let consent = "2026-07-26T00:00:00Z";
    let mac = routes::route_mac(
        key,
        "vault-test-0001",
        prefix,
        provider,
        CUSTOM_ORIGIN,
        443,
        consent,
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, custom_origin,
             custom_origin_port, custom_origin_mac, custom_origin_consent_at,
             created_at, updated_at)
         VALUES (?1, ?2, 1, ?3, 443, ?4, ?5, ?5, ?5)",
        rusqlite::params![prefix, provider, CUSTOM_ORIGIN, &mac[..], consent],
    )
    .unwrap();
}

/// A route table carrying a VERIFIED custom route whose origin has been
/// re-addressed to a synthetic local upstream, so the wire-level half can
/// run. Only the address is substituted; the route is only built at all if
/// the real MAC verification produced a `Ready` target for it, so a
/// verification regression fails these tests too.
#[cfg(unix)]
fn verified_custom_route_at(
    db: &std::path::Path,
    prefix: &str,
    key: &SecretBytes,
    port: u16,
) -> std::sync::Arc<routes::RouteState> {
    let conn = open_db(db);
    let table = routes::load_route_table(&conn, Some(key)).unwrap();
    let route = table
        .route(prefix)
        .unwrap_or_else(|| panic!("route '{prefix}' must load"));
    let resolved = match &route.target {
        RouteTarget::Ready(o) => o.clone(),
        other => panic!("the route must verify before it can be re-addressed: {other:?}"),
    };
    assert_eq!(resolved.host, CUSTOM_ORIGIN);
    let mut wire = routes::RouteTable::default();
    wire.insert_for_test(routes::Route {
        prefix: route.prefix.clone(),
        provider_id: route.provider_id.clone(),
        target: RouteTarget::Ready(routes::UpstreamOrigin {
            host: "127.0.0.1".to_string(),
            port,
        }),
        custom: true,
        usage_shape: route.usage_shape.clone(),
    });
    std::sync::Arc::new(routes::RouteState::from_table_for_test(wire))
}

#[cfg(unix)]
fn get(port: u16, path: &str) -> String {
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        sock,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {FAKE_KEY}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut got = String::new();
    let _ = sock.read_to_string(&mut got);
    got
}

// ---------------------------------------------------------------------------
// The core defect: a custom route must become usable through supported actions
// ---------------------------------------------------------------------------

/// Before the key is installed a custom route is unforwardable; after a
/// supported user action installs it, the SAME route resolves to its
/// registered origin AND really forwards. This is the audited functional
/// blocker, end to end.
#[cfg(unix)]
#[test]
fn a_custom_route_becomes_forwardable_once_the_key_is_installed() {
    let dir = service_dir();
    let db = test_db(dir.path());
    let key = route_key();
    register_custom_route(&db, "supa", "supabase", &key);
    let conn = open_db(&db);

    let before = routes::load_route_table(&conn, None).unwrap();
    assert_eq!(
        before.route("supa").map(|r| r.target.clone()),
        Some(RouteTarget::Unforwardable(Unforwardable::MacKeyUnavailable)),
        "precondition: with no key the route is unforwardable — the shipped bug \
         was that NOTHING ever moved it out of this state"
    );

    let after = routes::load_route_table(&conn, Some(&key)).unwrap();
    match after.route("supa").map(|r| r.target.clone()) {
        Some(RouteTarget::Ready(o)) => {
            assert_eq!(o.host, CUSTOM_ORIGIN);
            assert_eq!(o.port, 443);
        }
        other => panic!("the key must make the route forwardable, got {other:?}"),
    }

    // ...and a verified custom route really forwards through the listener.
    let upstream = MockUpstream::start(|sock, reqs| {
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).unwrap_or(0);
        reqs.lock().unwrap().push(buf[..n].to_vec());
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nfrom-up");
    });
    let mut gw = RunningGateway::start(verified_custom_route_at(&db, "supa", &key, upstream.port));
    let got = get(gw.port, "/supa/rest/v1/items");
    assert!(
        got.starts_with("HTTP/1.1 200 "),
        "the custom route must forward, got: {got:?}"
    );
    assert!(got.contains("from-up"), "the UPSTREAM body must arrive");
    assert!(
        !got.contains("unlock"),
        "a forwarded request must not produce the local 'unlock the vault' 503"
    );
    assert_eq!(upstream.request_count(), 1);
    assert!(
        upstream.first_request().contains("/rest/v1/items"),
        "the route prefix is stripped and the tail forwarded verbatim"
    );
    gw.stop();
}

/// The unavailable state still produces the documented 503 when the key is
/// absent — and the message must not promise something that does not happen.
#[cfg(unix)]
#[test]
fn a_custom_route_without_a_key_answers_503_not_a_forward() {
    let dir = service_dir();
    let db = test_db(dir.path());
    let key = route_key();
    register_custom_route(&db, "supa", "supabase", &key);
    let conn = open_db(&db);
    let table = routes::load_route_table(&conn, None).unwrap();
    let state = std::sync::Arc::new(routes::RouteState::from_table_for_test(table));
    let mut gw = RunningGateway::start(state);
    let got = get(gw.port, "/supa/rest/v1/items");
    assert!(
        got.starts_with("HTTP/1.1 503 "),
        "no key means an honest 503, got: {got:?}"
    );
    gw.stop();
}

/// The wiring, not just the unit: pushing the key over the real control
/// channel installs it into a real running service and status says so.
#[cfg(unix)]
#[test]
fn the_control_channel_installs_the_route_key_into_a_running_service() {
    let dir = service_dir();
    let _db = test_db(dir.path());
    let mut service = Service::start(dir.path(), 0).unwrap();

    assert!(
        !status(dir.path()).route_key_present,
        "a fresh service has no route key — nothing on disk can give it one"
    );

    push_route_key(dir.path(), &route_key());
    assert!(
        status(dir.path()).route_key_present,
        "the pushed key must be resident (this is the call that had NO callers)"
    );

    // And it can be dropped again.
    assert!(control::revoke_route_key(dir.path()));
    assert!(!status(dir.path()).route_key_present);
    service.stop();
}

// ---------------------------------------------------------------------------
// Fail-closed properties
// ---------------------------------------------------------------------------

/// A tampered origin still fails closed once the key IS present — the fix
/// must not turn "verify" into "accept".
#[cfg(unix)]
#[test]
fn a_tampered_origin_still_fails_closed_with_the_key_installed() {
    let dir = service_dir();
    let db = test_db(dir.path());
    let key = route_key();
    register_custom_route(&db, "supa", "supabase", &key);
    let conn = open_db(&db);
    conn.execute(
        "UPDATE gateway_routes SET custom_origin = 'attacker.example.com'
         WHERE route_prefix = 'supa'",
        [],
    )
    .unwrap();

    let table = routes::load_route_table(&conn, Some(&key)).unwrap();
    assert_eq!(
        table.route("supa").map(|r| r.target.clone()),
        Some(RouteTarget::Unforwardable(Unforwardable::MacMismatch)),
        "a rewritten origin must never forward, key present or not"
    );
}

/// The v2 MAC binds the route prefix. Without that binding a MAC'd row could
/// be TRANSPLANTED onto another prefix: the MAC would still verify, and a
/// request carrying (say) the OpenAI credential to `/openai/...` would be
/// forwarded to the Supabase origin.
#[cfg(unix)]
#[test]
fn a_maced_row_cannot_be_transplanted_onto_another_prefix() {
    let dir = service_dir();
    let db = test_db(dir.path());
    let key = route_key();
    register_custom_route(&db, "supa", "supabase", &key);
    let conn = open_db(&db);

    // Everything the old MAC covered is unchanged; only the prefix moves.
    conn.execute(
        "UPDATE gateway_routes SET route_prefix = 'other' WHERE route_prefix = 'supa'",
        [],
    )
    .unwrap();

    let table = routes::load_route_table(&conn, Some(&key)).unwrap();
    assert_eq!(
        table.route("other").map(|r| r.target.clone()),
        Some(RouteTarget::Unforwardable(Unforwardable::MacMismatch)),
        "the MAC must bind the route prefix, or an origin can be moved under \
         a different provider's credential"
    );
    assert!(table.route("supa").is_none());
}

/// A stored port other than 443 must be re-validated at load, not silently
/// re-checked as if it were 443. The MAC covers the port, so this is
/// defense in depth — which is exactly what the code claims to provide.
#[cfg(unix)]
#[test]
fn a_stored_non_443_port_is_rejected_at_load_even_with_a_valid_mac() {
    let dir = service_dir();
    let db = test_db(dir.path());
    let key = route_key();
    let conn = open_db(&db);
    let consent = "2026-07-26T00:00:00Z";
    // A correctly-MAC'd row over a PUBLIC host on a non-443 port.
    let mac = routes::route_mac(
        &key,
        "vault-test-0001",
        "supa",
        "supabase",
        "myref.supabase.co",
        8443,
        consent,
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, custom_origin,
             custom_origin_port, custom_origin_mac, custom_origin_consent_at,
             created_at, updated_at)
         VALUES ('supa', 'supabase', 1, 'myref.supabase.co', 8443, ?1, ?2, ?2, ?2)",
        rusqlite::params![&mac[..], consent],
    )
    .unwrap();

    let table = routes::load_route_table(&conn, Some(&key)).unwrap();
    assert!(
        table.route("supa").is_none(),
        "the load-time origin re-check must see the STORED port, not a \
         synthesized 443"
    );
    assert!(
        table
            .skipped
            .iter()
            .any(|(p, why)| p == "supa" && why.contains("443")),
        "and it must say why: {:?}",
        table.skipped
    );
}

/// Removing the route stops forwarding, key or no key.
#[cfg(unix)]
#[test]
fn removing_or_disabling_a_custom_route_stops_forwarding() {
    let dir = service_dir();
    let db = test_db(dir.path());
    let key = route_key();
    register_custom_route(&db, "supa", "supabase", &key);
    let conn = open_db(&db);

    // Disabled: invisible to the snapshot (404), counted as disabled.
    routes::set_route_enabled(&conn, "supa", false).unwrap();
    let table = routes::load_route_table(&conn, Some(&key)).unwrap();
    assert!(
        table.route("supa").is_none(),
        "a disabled route matches nothing"
    );
    assert_eq!(table.disabled, 1);

    // Removed: gone entirely.
    routes::set_route_enabled(&conn, "supa", true).unwrap();
    assert!(routes::remove_route(&conn, "supa").unwrap());
    let table = routes::load_route_table(&conn, Some(&key)).unwrap();
    assert!(table.route("supa").is_none());
    assert_eq!(table.disabled, 0);
}

/// The gateway never accepts a request-selected origin, custom routes or
/// not: an unknown prefix 404s and no upstream is contacted.
#[cfg(unix)]
#[test]
fn an_unregistered_origin_is_never_reachable_through_a_custom_route() {
    let upstream = MockUpstream::start(|sock, reqs| {
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).unwrap_or(0);
        reqs.lock().unwrap().push(buf[..n].to_vec());
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    });
    let dir = service_dir();
    let db = test_db(dir.path());
    let key = route_key();
    register_custom_route(&db, "supa", "supabase", &key);
    let mut gw = RunningGateway::start(verified_custom_route_at(&db, "supa", &key, upstream.port));

    for path in [
        "/unknown/v1/x",                // no such route
        "/supa2/v1/x",                  // prefix confusion
        "http://evil.example.com/v1/x", // absolute form
        "/supa/../unknown/v1/x",        // traversal
    ] {
        let got = get(gw.port, path);
        assert!(
            !got.starts_with("HTTP/1.1 200 "),
            "{path} must not be forwarded, got: {got:?}"
        );
    }
    assert_eq!(
        upstream.request_count(),
        0,
        "no request-selected origin may ever be dialed"
    );
    gw.stop();
}

// ---------------------------------------------------------------------------
// Lock and restart behavior (the documented, deliberate difference from the
// matching key)
// ---------------------------------------------------------------------------

/// The route key is NOT dropped on vault lock. Dropping it would stop
/// forwarding for custom routes, breaking forward-while-locked (ADR 0019 D4)
/// for no security gain: unlike the matching key it verifies route integrity
/// only and cannot confirm anything about a credential. Locking still drops
/// the MATCHING key, which this test also asserts so the two cannot be
/// conflated.
#[cfg(unix)]
#[test]
fn a_vault_lock_keeps_the_route_key_but_drops_the_matching_key() {
    const MATCH_KEY_HEX: &str = "3c1f0a5b8e2d47690a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071";
    let dir = service_dir();
    let _db = test_db(dir.path());
    let mut service = Service::start(dir.path(), 0).unwrap();
    let nonce = control::read_nonce(dir.path()).unwrap().to_string();

    push_route_key(dir.path(), &route_key());
    assert_eq!(
        control::send(
            dir.path(),
            &Request::PushKey {
                nonce: nonce.clone(),
                key_hex: MATCH_KEY_HEX.into(),
            }
        )
        .unwrap(),
        Response::Ok
    );
    let before = status(dir.path());
    assert!(before.route_key_present && before.matching_key_present);

    assert!(control::notify_vault_locked(dir.path(), Some(15)));

    let after = status(dir.path());
    assert!(
        !after.matching_key_present,
        "the matching key IS dropped on lock (SI-9)"
    );
    assert!(
        after.route_key_present,
        "the route key is NOT dropped on lock — custom routes must keep \
         forwarding while the vault is locked (ADR 0021)"
    );
    service.stop();
}

/// A restart drops the route key, exactly like the matching key: nothing
/// persists it. Custom routes are unavailable until a vault session installs
/// it again — the documented "locked since boot" outage window.
#[cfg(unix)]
#[test]
fn a_restarted_service_has_no_route_key_until_a_session_installs_one() {
    let dir = service_dir();
    let _db = test_db(dir.path());

    let mut first = Service::start(dir.path(), 0).unwrap();
    push_route_key(dir.path(), &route_key());
    assert!(status(dir.path()).route_key_present);
    first.stop();

    let mut second = Service::start(dir.path(), 0).unwrap();
    assert!(
        !status(dir.path()).route_key_present,
        "a restart must not resurrect the route key from anything on disk"
    );
    // ...and a supported action brings it back.
    push_route_key(dir.path(), &route_key());
    assert!(status(dir.path()).route_key_present);
    second.stop();
}

/// The route key push is refused without the control nonce, exactly like
/// every other privileged operation.
#[cfg(unix)]
#[test]
fn pushing_a_route_key_requires_the_control_nonce() {
    let dir = service_dir();
    let _db = test_db(dir.path());
    let mut service = Service::start(dir.path(), 0).unwrap();

    let wrong = "0".repeat(control::read_nonce(dir.path()).unwrap().len());
    match control::send(
        dir.path(),
        &Request::PushRouteKey {
            nonce: wrong.clone(),
            key_hex: "c5".repeat(32),
        },
    )
    .unwrap()
    {
        Response::Error { code, .. } => assert_eq!(code, "unauthorized"),
        other => panic!("must be refused, got {other:?}"),
    }
    match control::send(dir.path(), &Request::RevokeRouteKey { nonce: wrong }).unwrap() {
        Response::Error { code, .. } => assert_eq!(code, "unauthorized"),
        other => panic!("must be refused, got {other:?}"),
    }
    assert!(!status(dir.path()).route_key_present);
    service.stop();
}

/// A malformed route key is refused rather than installed.
#[cfg(unix)]
#[test]
fn a_malformed_route_key_is_refused() {
    let dir = service_dir();
    let _db = test_db(dir.path());
    let mut service = Service::start(dir.path(), 0).unwrap();
    let nonce = control::read_nonce(dir.path()).unwrap().to_string();

    for bad in ["", "zz", "c5", &"c5".repeat(31), &"c5".repeat(33)] {
        match control::send(
            dir.path(),
            &Request::PushRouteKey {
                nonce: nonce.clone(),
                key_hex: bad.to_string(),
            },
        )
        .unwrap()
        {
            Response::Error { code, .. } => assert_eq!(code, "invalid_input", "for {bad:?}"),
            other => panic!("{bad:?} must be refused, got {other:?}"),
        }
        assert!(!status(dir.path()).route_key_present);
    }
    service.stop();
}

/// The route key is a DIFFERENT key from the matching key, and neither is
/// derived from the other. Pushing one must never make the other present.
#[cfg(unix)]
#[test]
fn the_route_key_and_the_matching_key_are_independent() {
    let dir = service_dir();
    let _db = test_db(dir.path());
    let mut service = Service::start(dir.path(), 0).unwrap();

    push_route_key(dir.path(), &route_key());
    let s = status(dir.path());
    assert!(s.route_key_present);
    assert!(
        !s.matching_key_present,
        "a route key must never enable credential attribution"
    );

    assert!(control::send_revoke_key(dir.path()));
    assert!(
        status(dir.path()).route_key_present,
        "revoking the MATCHING key must not disturb route verification"
    );
    service.stop();
}
