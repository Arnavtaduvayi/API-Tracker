//! The spend-cap gate (Increment 08, ADR 0032; MESH-SI-9/10, SI-22): real
//! vaults with a mesh and a cap, the real writer, the real `CapGate`, and a
//! local mock upstream on the plain test connector. The poller is driven by
//! hand (`CapGate::refresh`), so each step is deterministic. A second vault,
//! paired with core's own steps and replicated through the sans-IO session,
//! grants rights for the end-to-end case. The gateway links core only.

mod common;

use api_tracker_core::mesh::caps::{self, escrow, AssumeNotRunning, AssumeRunning};
use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::kinds::MeshSetting;
use api_tracker_core::mesh::membership::{self, PendingIdentity};
use api_tracker_core::mesh::proto::{Action, DirectMsg, Frame, Limits, Session};
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::{Draft, HlcPolicy, MeshStore};
use api_tracker_core::mesh::{projects, DeviceId, MeshProjectId};
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, NewProject, UnlockedVault, VaultPaths};
use api_tracker_gateway::capgate::CapGate;
use api_tracker_gateway::forward::Gateway;
use api_tracker_gateway::routes::{
    LinkInfo, Route, RouteState, RouteTable, RouteTarget, UpstreamOrigin,
};
use api_tracker_gateway::server::{self, Listener};
use api_tracker_gateway::writer::Writer;
use common::*;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

const PW: &str = "cap-gate-master-password-1";
const SLUG: &str = "cccccccccccccccccccccccccccccccc";
const ANT_SLUG: &str = "dddddddddddddddddddddddddddddddd";
const USD: u64 = 1_000_000;

struct Dev {
    _dir: tempfile::TempDir,
    paths: VaultPaths,
    v: UnlockedVault,
    app: String,
}

fn dev() -> Dev {
    std::env::set_var("API_TRACKER_INSECURE_FAST_KDF", "1");
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("data"));
    let mut v = vault::create_vault(&paths, &SecretString::from(PW)).unwrap();
    let app = v
        .create_project(NewProject {
            name: "app".into(),
            ..Default::default()
        })
        .unwrap()
        .id;
    Dev {
        _dir: dir,
        paths,
        v,
        app,
    }
}

fn store(d: &Dev) -> SqliteStore {
    d.v.mesh_open_store().unwrap()
}

/// A device in a mesh of its own with `app` shared and a `usd` cap on it,
/// enforcement `on` or not.
fn capped(usd_micros: u64, on: bool) -> (Dev, MeshProjectId) {
    let d = dev();
    d.v.mesh_init("laptop").unwrap();
    let (p, _) = d.v.mesh_project_share(&d.app).unwrap();
    d.v.mesh_cap_create(&p.to_hex(), usd_micros, &AssumeNotRunning)
        .unwrap();
    if on {
        d.v.mesh_cap_enforce(&SecretString::from(PW), None, true)
            .unwrap();
    }
    (d, p)
}

fn json_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// `/v1/big`: 100 000 + 50 000 gpt-4o tokens; `/v1/small`: 10 + 5;
/// `/v1/slow`: small after 600 ms; `/v1/fail`: closes with no response;
/// `/v1/unpriced`: a model nothing prices.
fn upstream() -> MockUpstream {
    MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        let text = String::from_utf8_lossy(&head).to_string();
        requests.lock().unwrap().push(head);
        let tokens = |p: u64, c: u64, model: &str| {
            format!(
                r#"{{"model":"{model}","usage":{{"prompt_tokens":{p},"completion_tokens":{c},"total_tokens":{}}}}}"#,
                p + c
            )
        };
        let body = if text.contains("/v1/slowbig") {
            std::thread::sleep(Duration::from_millis(400));
            tokens(100_000, 50_000, "gpt-4o")
        } else if text.contains("/v1/big") {
            tokens(100_000, 50_000, "gpt-4o")
        } else if text.contains("/v1/nousage") {
            r#"{"model":"gpt-4o","choices":[]}"#.to_owned()
        } else if text.contains("/v1/unpriced") {
            tokens(10, 5, "no-such-model-x9")
        } else if text.contains("/v1/fail") {
            return; // closes without a response
        } else {
            if text.contains("/v1/slow") {
                std::thread::sleep(Duration::from_millis(600));
            }
            if text.contains("/v1/messages") {
                r#"{"model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":10,"output_tokens":5}}"#
                    .to_owned()
            } else {
                tokens(10, 5, "gpt-4o")
            }
        };
        let _ = sock.write_all(json_response(&body).as_bytes());
        let _ = sock.flush();
    })
}

struct Running {
    _writer: Writer,
    port: u16,
    gate: Arc<CapGate>,
}

/// The gateway on `d`'s database with its writer and gate, `d`'s `app`
/// linked to an OpenAI-style and an Anthropic-style route.
fn gateway(d: &Dev, upstream_port: u16, paused: bool) -> Running {
    let db_path = d.paths.db_path();
    let writer = Writer::start(&db_path, "boot-caps".into());
    let mut table = RouteTable::default();
    for (prefix, shape, slug) in [
        ("openai", "openai", SLUG),
        ("anthropic", "anthropic", ANT_SLUG),
    ] {
        table.insert_for_test(Route {
            prefix: prefix.into(),
            provider_id: prefix.into(),
            target: RouteTarget::Ready(UpstreamOrigin {
                host: "127.0.0.1".into(),
                port: upstream_port,
            }),
            custom: false,
            usage_shape: shape.into(),
        });
        table.insert_link_for_test(LinkInfo {
            project_id: d.app.clone(),
            route_prefix: prefix.into(),
            link_slug: slug.into(),
        });
    }
    let routes = Arc::new(RouteState::from_table_for_test(table));
    let gate = Arc::new(CapGate::new(&db_path));
    gate.refresh(&providers());
    let listener = Listener::bind(0).unwrap();
    let port = listener.port();
    let mut gw = Gateway::new(routes, writer.sink(), port);
    gw.connector = Arc::new(api_tracker_gateway::upstream::InsecurePlainConnectorForTests);
    gw.capgate = Some(gate.clone());
    gw.recording_paused
        .store(paused, std::sync::atomic::Ordering::Relaxed);
    std::thread::spawn(move || server::serve_with_taps(gw, listener, server::usage_tap_factory()));
    Running {
        _writer: writer,
        port,
        gate,
    }
}

fn providers() -> Vec<String> {
    vec!["anthropic".into(), "openai".into()]
}

/// One request; returns the whole response.
fn request(port: u16, path: &str) -> String {
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let route = if path.starts_with("/v1/messages") {
        format!("/p/{ANT_SLUG}/anthropic")
    } else {
        format!("/p/{SLUG}/openai")
    };
    let req = format!(
        "POST {route}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Authorization: Bearer {FAKE_KEY}\r\nx-api-key: {FAKE_KEY}\r\n\
         Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    c.write_all(req.as_bytes()).unwrap();
    String::from_utf8_lossy(&read_to_close(&mut c)).to_string()
}

fn status_line(resp: &str) -> &str {
    resp.lines().next().unwrap_or("")
}

fn body(resp: &str) -> serde_json::Value {
    let b = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(b).unwrap_or(serde_json::Value::Null)
}

fn avail(gate: &CapGate) -> i64 {
    gate.status().caps[0].avail_micros
}

/// gpt-4o's estimate for `p` + `c` tokens, as the writer computes it.
fn cost(d: &Dev, p: i64, c: i64) -> u64 {
    let now = api_tracker_core::clock::now_rfc3339();
    api_tracker_core::pricing::estimate_token_cost_as_of(
        d.v.connection(),
        "openai",
        "gpt-4o",
        &now,
        p,
        c,
    )
    .unwrap()
    .unwrap()
    .micros as u64
}

fn persisted_cost(d: &Dev) -> u64 {
    d.v.connection()
        .query_row(
            "SELECT COALESCE(SUM(estimated_cost_micros), 0) FROM gateway_usage_daily",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as u64
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn under_the_cap_requests_forward_and_spend_is_counted_once_across_the_writer() {
    let (d, _) = capped(100 * USD, true);
    let up = upstream();
    let gw = gateway(&d, up.port, false);
    let before = avail(&gw.gate);
    assert_eq!(before, 100 * USD as i64);
    let resp = request(gw.port, "/v1/small");
    assert!(status_line(&resp).contains("200"), "{resp}");
    let c = cost(&d, 10, 5) as i64;
    assert!(c > 0);
    // Charged in memory at once, before the writer persisted it.
    assert_eq!(avail(&gw.gate), before - c);
    wait_for("the writer", || persisted_cost(&d) == c as u64);
    assert_eq!(avail(&gw.gate), before - c, "persisted, not yet re-read");
    gw.gate.refresh(&providers());
    assert_eq!(avail(&gw.gate), before - c, "re-read: counted once");
    gw.gate.refresh(&providers());
    assert_eq!(avail(&gw.gate), before - c);
    // An unpriced model is admitted and counted as unpriced, not charged.
    let resp = request(gw.port, "/v1/unpriced");
    assert!(status_line(&resp).contains("200"));
    assert_eq!(gw.gate.status().caps[0].unpriced_requests, 1);
    assert_eq!(avail(&gw.gate), before - c);
}

#[test]
fn at_exhaustion_a_non_retryable_403_is_sent_before_any_upstream_byte() {
    // $1: the first big request ($0.75) leaves $0.25, near exhaustion; the
    // second is admitted alone and overshoots; the third is refused.
    let (d, _) = capped(USD, true);
    let up = upstream();
    let gw = gateway(&d, up.port, false);
    assert!(status_line(&request(gw.port, "/v1/big")).contains("200"));
    assert!(status_line(&request(gw.port, "/v1/big")).contains("200"));
    assert!(avail(&gw.gate) < 0, "one request's overshoot");
    let seen = up.request_count();
    let resp = request(gw.port, "/v1/big");
    assert!(status_line(&resp).starts_with("HTTP/1.1 403"), "{resp}");
    assert!(!status_line(&resp).contains("429"));
    assert_eq!(up.request_count(), seen, "the upstream saw nothing");
    let lower = resp.to_ascii_lowercase();
    assert!(lower.contains("content-type: application/json"), "{resp}");
    let cap = gw.gate.status().caps[0].cap_id.clone();
    let month = gw.gate.status().caps[0].month.clone();
    assert!(
        lower.contains(&format!("x-tethra-cap: exceeded; cap={cap}; month={month}")),
        "{resp}"
    );
    let b = body(&resp);
    assert_eq!(b["error"]["type"], "tethra_spend_cap");
    assert_eq!(b["error"]["code"], "spend_cap_exceeded");
    assert!(b["error"]["message"]
        .as_str()
        .unwrap()
        .contains("tethra mesh cap raise"));
    // No credential or authorization bytes in the refusal.
    assert!(
        !resp.contains(FAKE_KEY) && !lower.contains("bearer"),
        "{resp}"
    );
    // Anthropic routes get Anthropic's error shape.
    let resp = request(gw.port, "/v1/messages");
    assert!(status_line(&resp).starts_with("HTTP/1.1 403"), "{resp}");
    let b = body(&resp);
    assert_eq!(b["type"], "error");
    assert_eq!(b["error"]["type"], "tethra_spend_cap");
    assert_eq!(gw.gate.status().caps[0].refused_requests, 2);
    // It stays refused across a re-read (the writer persisted the overshoot).
    wait_for("the writer", || {
        persisted_cost(&d) >= 2 * cost(&d, 100_000, 50_000)
    });
    gw.gate.refresh(&providers());
    assert!(status_line(&request(gw.port, "/v1/small")).starts_with("HTTP/1.1 403"));
}

#[test]
fn near_exhaustion_one_request_at_a_time_and_the_slot_clears_on_every_exit() {
    // $0.40 is below the $0.50 floor: one at a time from the start.
    let (d, _) = capped(400_000, true);
    let up = upstream();
    let gw = gateway(&d, up.port, false);
    assert!(gw.gate.status().caps[0].near_exhaustion);
    let port = gw.port;
    let handles: Vec<_> = (0..8)
        .map(|_| std::thread::spawn(move || request(port, "/v1/slow")))
        .collect();
    let resps: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let ok = resps
        .iter()
        .filter(|r| status_line(r).contains("200"))
        .count();
    let serialized = resps
        .iter()
        .filter(|r| {
            status_line(r).contains("403")
                && r.to_ascii_lowercase()
                    .contains("reason=cap_near_exhaustion_serialized")
        })
        .count();
    assert_eq!((ok, serialized), (1, 7), "{resps:?}");
    // After completion the slot is free again.
    assert!(status_line(&request(port, "/v1/small")).contains("200"));
    // An upstream that fails: the slot still clears.
    let resp = request(port, "/v1/fail");
    assert!(!status_line(&resp).contains("200"), "{resp}");
    assert!(status_line(&request(port, "/v1/small")).contains("200"));
    // A client that disconnects mid-exchange: the slot clears too.
    {
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let req = format!(
            "POST /p/{SLUG}/openai/v1/slow HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        );
        c.write_all(req.as_bytes()).unwrap();
    }
    std::thread::sleep(Duration::from_millis(900));
    assert!(status_line(&request(port, "/v1/small")).contains("200"));
}

#[test]
fn only_caps_switched_on_here_are_enforced_and_a_peer_cannot_switch_one_on() {
    let (d, _) = capped(USD, false);
    let up = upstream();
    let gw = gateway(&d, up.port, false);
    for _ in 0..3 {
        assert!(status_line(&request(gw.port, "/v1/big")).contains("200"));
    }
    let st = gw.gate.status();
    assert!(!st.caps[0].enforced);
    assert!(st.caps[0].avail_micros < 0, "counted, not enforced");
    assert!(st
        .inactive_reason
        .unwrap()
        .contains("no spend cap is enforced"));
    // A replicated setting cannot switch it on: only the local switch can.
    let keys = d.v.mesh_keys().unwrap();
    let mut s = store(&d);
    for name in ["cap_enforce", "cap-enforcement"] {
        s.mint(
            keys.signing_key(),
            Draft::of(
                &MeshSetting {
                    name: name.into(),
                    value: serde_json::json!(1),
                },
                HlcPolicy::Now,
            ),
        )
        .unwrap();
    }
    drop(s);
    gw.gate.refresh(&providers());
    assert!(status_line(&request(gw.port, "/v1/small")).contains("200"));
    // Switched on here (reauthenticated), it holds within one poll.
    d.v.mesh_cap_enforce(&SecretString::from(PW), Some("app"), true)
        .unwrap();
    gw.gate.refresh(&providers());
    assert!(status_line(&request(gw.port, "/v1/small")).starts_with("HTTP/1.1 403"));
    // A wrong password changes nothing.
    assert!(d
        .v
        .mesh_cap_enforce(&SecretString::from("wrong-password"), None, false)
        .is_err());
    d.v.mesh_cap_enforce(&SecretString::from(PW), None, false)
        .unwrap();
    gw.gate.refresh(&providers());
    assert!(status_line(&request(gw.port, "/v1/small")).contains("200"));
}

#[test]
fn the_gate_fails_open_and_says_why() {
    let up = upstream();
    // No mesh.
    let plain = dev();
    let gw = gateway(&plain, up.port, false);
    assert!(status_line(&request(gw.port, "/v1/small")).contains("200"));
    assert!(gw
        .gate
        .status()
        .inactive_reason
        .unwrap()
        .contains("not in a mesh"));
    // A database that cannot be opened.
    let missing = CapGate::new(std::path::Path::new("/nonexistent/tethra/vault.db"));
    missing.refresh(&providers());
    assert!(missing
        .status()
        .inactive_reason
        .unwrap()
        .contains("could not be opened"));
    // A database at a newer schema than this gateway.
    let (d, _) = capped(USD, true);
    let newer = d.paths.data_dir.join("newer.db");
    std::fs::copy(d.paths.db_path(), &newer).unwrap();
    let c = rusqlite::Connection::open(&newer).unwrap();
    c.pragma_update(None, "user_version", 9_999).unwrap();
    drop(c);
    let gate = CapGate::new(&newer);
    gate.refresh(&providers());
    assert!(gate
        .status()
        .inactive_reason
        .unwrap()
        .contains("schema version"));
    // A stale snapshot (a stuck poller): admitted, and said.
    let up2 = upstream();
    let gw = gateway(&d, up2.port, false);
    for _ in 0..2 {
        request(gw.port, "/v1/big");
    }
    assert!(status_line(&request(gw.port, "/v1/small")).starts_with("HTTP/1.1 403"));
    let stale =
        CapGate::new(&d.paths.db_path()).with_stale_after_for_test(Duration::from_millis(1));
    stale.refresh(&providers());
    std::thread::sleep(Duration::from_millis(5));
    assert!(stale.status().inactive_reason.unwrap().contains("stale"));
}

#[test]
fn a_charge_the_writer_never_persists_stays_counted_and_marks_accounting_incomplete() {
    let (d, _) = capped(100 * USD, true);
    let up = upstream();
    // Recording paused: nothing reaches the writer.
    let gw = gateway(&d, up.port, true);
    assert!(status_line(&request(gw.port, "/v1/small")).contains("200"));
    let c = cost(&d, 10, 5) as i64;
    gw.gate.refresh(&providers());
    let st = gw.gate.status();
    assert_eq!(
        st.caps[0].avail_micros,
        100 * USD as i64 - c,
        "never missed"
    );
    assert!(st.caps[0].accounting_incomplete);
    assert_eq!(persisted_cost(&d), 0);
}

fn enforce_global(d: &Dev) {
    d.v.mesh_cap_enforce(&SecretString::from(PW), None, true)
        .unwrap();
}

/// One sans-IO session between two devices, with rights requests carried
/// as Direct frames and answered after the commit (as the node does).
fn exchange(a: &Dev, b: &Dev) {
    let (mut sa_store, mut sb_store) = (store(a), store(b));
    let (ia, ib) = (sa_store.self_id(), sb_store.self_id());
    let mut sa = Session::new(Limits::default(), Some(ib));
    let mut sb = Session::new(Limits::default(), Some(ia));
    let (mut to_a, mut to_b): (Vec<Frame>, Vec<Frame>) = (Vec::new(), Vec::new());
    let (mut held_a, mut held_b) = (Vec::new(), Vec::new());
    fn route(
        acts: Vec<Action>,
        out: &mut Vec<Frame>,
        held: &mut Vec<DirectMsg>,
        s: &mut SqliteStore,
    ) {
        for act in acts {
            match act {
                Action::Send(f) => out.push(f),
                Action::Commit(batch) => {
                    s.commit(batch).unwrap();
                }
                Action::Direct(m) => held.push(m),
                _ => {}
            }
        }
    }
    fn asks(session: &mut Session, s: &SqliteStore, peer: &DeviceId) -> Vec<Action> {
        caps::rights_requests(s, peer)
            .unwrap()
            .into_iter()
            .flat_map(|a| {
                session.direct(DirectMsg::RightsRequest {
                    cap: a.cap,
                    month: a.month,
                    want: a.want,
                    reclaim: a.reclaim,
                })
            })
            .collect()
    }
    let acts = sa.start(&sa_store);
    route(acts, &mut to_b, &mut held_a, &mut sa_store);
    let acts = asks(&mut sa, &sa_store, &ib);
    route(acts, &mut to_b, &mut held_a, &mut sa_store);
    let acts = sb.start(&sb_store);
    route(acts, &mut to_a, &mut held_b, &mut sb_store);
    let acts = asks(&mut sb, &sb_store, &ia);
    route(acts, &mut to_a, &mut held_b, &mut sb_store);
    for _ in 0..1000 {
        if to_a.is_empty() && to_b.is_empty() {
            break;
        }
        for f in std::mem::take(&mut to_b) {
            let acts = sb.on_frame(f, &sb_store);
            route(acts, &mut to_a, &mut held_b, &mut sb_store);
        }
        for f in std::mem::take(&mut to_a) {
            let acts = sa.on_frame(f, &sa_store);
            route(acts, &mut to_b, &mut held_a, &mut sa_store);
        }
    }
    for (held, s, d, peer) in [
        (held_a, &mut sa_store, a, ib),
        (held_b, &mut sb_store, b, ia),
    ] {
        for m in held {
            if let DirectMsg::RightsRequest {
                cap,
                month,
                want,
                reclaim,
            } = m
            {
                let keys = d.v.mesh_keys().unwrap();
                let ask = caps::RightsAsk {
                    cap,
                    month,
                    want,
                    reclaim,
                };
                caps::grant(s, keys.signing_key(), &AssumeNotRunning, &peer, ask).unwrap();
            }
        }
    }
    for (s, peer) in [(&sa_store, ib), (&sb_store, ia)] {
        membership::log_exchange(
            s.connection(),
            &membership::ExchangeRecord {
                peer_device: Some(peer),
                direction: "outbound",
                items_in: 0,
                items_out: 0,
                result: "ok",
                error: None,
            },
        )
        .unwrap();
    }
}

/// `b` joins `a`'s mesh with core's pairing steps.
fn join(a: &Dev, b: &Dev) {
    let inv =
        a.v.mesh_invite_create(&SecretString::from(PW), None)
            .unwrap();
    let pending = PendingIdentity::generate("desktop").unwrap();
    let req = pending.request();
    let access =
        a.v.mesh_vault()
            .access_keys(a.v.connection(), SystemClock.now_ms())
            .unwrap()
            .current;
    let keys = a.v.mesh_keys().unwrap();
    let accept = membership::accept_pairing(
        &mut store(a),
        keys.signing_key(),
        &inv.token.hash(),
        &req,
        &req.noise_pub,
        &access,
    )
    .unwrap();
    b.v.mesh_join(&pending, &accept).unwrap();
    exchange(a, b);
}

#[test]
fn the_fence_reserves_before_a_transfer_publishes_and_never_subtracts_twice() {
    let a = dev();
    a.v.mesh_init("laptop").unwrap();
    let b = dev();
    join(&a, &b);
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    exchange(&a, &b);
    // Enforcement on (an empty cap list switches nothing, so create first
    // with the gateway "running": the share for B waits in escrow).
    let keys = a.v.mesh_keys().unwrap();
    let cap = caps::create(
        &mut store(&a),
        keys.signing_key(),
        &AssumeNotRunning,
        &p,
        100 * USD,
    )
    .unwrap()
    .cap_id;
    // That share was published at once (enforcement was off). Raise with
    // enforcement on and the gateway running: B's extra share is fenced.
    enforce_global(&a);
    caps::raise(
        &mut store(&a),
        keys.signing_key(),
        &AssumeRunning,
        &cap,
        20 * USD,
    )
    .unwrap();
    let open = escrow::open_rows(a.v.connection()).unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].amount_micros, 10 * USD);
    // A gateway that starts now counts the pending reservation in its first
    // snapshot, and acknowledges it.
    let up = upstream();
    let gw = gateway(&a, up.port, false);
    let reserved = avail(&gw.gate);
    assert_eq!(
        reserved,
        (120 - 50 - 10) as i64 * USD as i64,
        "rights − escrow"
    );
    let acked = escrow::open_rows(a.v.connection()).unwrap();
    assert_eq!(acked[0].state, escrow::EscrowState::Acked);
    assert!(acked[0].acked_generation.is_some());
    // The node publishes it; the gate's figure does not move again. (From
    // the 20th the same run mints next month, whose shares are fenced in
    // turn; this month's row is what matters here.)
    caps::reconcile(&mut store(&a), keys.signing_key(), &AssumeRunning).unwrap();
    let row = escrow::rows(a.v.connection(), 10)
        .unwrap()
        .into_iter()
        .find(|r| r.id == acked[0].id)
        .unwrap();
    assert_eq!(row.state, escrow::EscrowState::Published);
    assert_eq!(avail(&gw.gate), reserved, "before the re-read");
    gw.gate.refresh(&providers());
    assert_eq!(avail(&gw.gate), reserved, "after: counted once");
}

#[test]
fn end_to_end_a_403_then_rights_from_another_device_admit_again() {
    let a = dev();
    a.v.mesh_init("laptop").unwrap();
    let b = dev();
    join(&a, &b);
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    exchange(&a, &b);
    projects::bind(&store(&b), &p, &b.app).unwrap();
    // B owns a $4 cap; A, active, gets $2.
    let kb = b.v.mesh_keys().unwrap();
    let cap = caps::create(
        &mut store(&b),
        kb.signing_key(),
        &AssumeNotRunning,
        &p,
        4 * USD,
    )
    .unwrap()
    .cap_id;
    exchange(&a, &b);
    a.v.mesh_cap_enforce(&SecretString::from(PW), None, true)
        .unwrap();
    let up = upstream();
    let gw = gateway(&a, up.port, false);
    assert_eq!(avail(&gw.gate), 2 * USD as i64);
    // A spends its $2 (and one request over) through its gateway: refused.
    let mut refused = false;
    for _ in 0..6 {
        if status_line(&request(gw.port, "/v1/big")).starts_with("HTTP/1.1 403") {
            refused = true;
            break;
        }
    }
    assert!(refused, "A was refused");
    wait_for("the writer", || persisted_cost(&a) > 0);
    caps::reconcile(
        &mut store(&a),
        a.v.mesh_keys().unwrap().signing_key(),
        &AssumeNotRunning,
    )
    .unwrap();
    // A asks B in an exchange; B grants after it; the next one delivers.
    exchange(&a, &b);
    exchange(&a, &b);
    let f = caps::view::month_figures(
        store(&a).state(),
        &caps::view::cap_in(store(&a).state(), &cap).unwrap(),
        caps::period::month_of(SystemClock.now_ms()),
    );
    assert!(
        f.device(&store(&a).self_id()).received > 2 * u128::from(USD),
        "B granted A rights"
    );
    gw.gate.refresh(&providers());
    assert!(avail(&gw.gate) > 0, "{}", avail(&gw.gate));
    assert!(status_line(&request(gw.port, "/v1/small")).contains("200"));
}

#[test]
fn the_gate_status_is_persisted_for_the_cli() {
    let (d, _) = capped(5 * USD, true);
    let up = upstream();
    let gw = gateway(&d, up.port, false);
    let st = caps::gate::read_status(d.v.connection()).unwrap().unwrap();
    assert!(st.inactive_reason.is_none(), "{st:?}");
    assert_eq!(st.caps.len(), 1);
    assert!(st.caps[0].enforced);
    assert_eq!(st.caps[0].avail_micros, 5 * USD as i64);
    let report = caps::report(&store(&d), None, None).unwrap();
    assert!(report.gate_fresh);
    assert!(report.caps[0].enforced_here);
    drop(gw);
}

#[test]
fn a_refused_request_with_a_large_body_still_reads_a_clean_403_not_a_reset() {
    let (d, _) = capped(USD, true);
    let up = upstream();
    let gw = gateway(&d, up.port, false);
    for _ in 0..2 {
        request(gw.port, "/v1/big");
    }
    // A 1 MiB body sent in pieces after the head, as an SDK does.
    let mut c = std::net::TcpStream::connect(("127.0.0.1", gw.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let len = 1 << 20;
    let head = format!(
        "POST /p/{SLUG}/openai/v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\
         Authorization: Bearer {FAKE_KEY}\r\nContent-Type: application/json\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n",
        gw.port
    );
    c.write_all(head.as_bytes()).unwrap();
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..(len / chunk.len()) {
        // The gateway may have answered already; it must keep reading.
        c.write_all(&chunk).unwrap();
        std::thread::sleep(Duration::from_millis(2));
    }
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        status_line(&resp).starts_with("HTTP/1.1 403"),
        "{resp:.200}"
    );
    assert_eq!(body(&resp)["error"]["code"], "spend_cap_exceeded");
}

#[test]
fn concurrent_requests_reserve_their_typical_cost_so_overshoot_stays_bounded() {
    let (d, _) = capped(5 * USD, true);
    let up = upstream();
    let gw = gateway(&d, up.port, false);
    // History: a typical request costs $0.75 (the p95 the gate reserves).
    request(gw.port, "/v1/big");
    wait_for("the writer", || persisted_cost(&d) > 0);
    gw.gate.refresh(&providers());
    let one = cost(&d, 100_000, 50_000) as i64;
    let left = avail(&gw.gate);
    let port = gw.port;
    let handles: Vec<_> = (0..20)
        .map(|_| std::thread::spawn(move || request(port, "/v1/slowbig")))
        .collect();
    let ok = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|r| status_line(r).contains("200"))
        .count() as i64;
    assert!((1..20).contains(&ok), "{ok} admitted");
    // Whatever ran concurrently fit its reservations: no overshoot beyond
    // one request.
    assert!(left - ok * one >= -one, "left {left}, {ok} × {one}");
    assert!(avail(&gw.gate) >= -one);
}

#[test]
fn responses_without_usage_are_counted_as_unmetered() {
    let (d, _) = capped(100 * USD, true);
    let up = upstream();
    let gw = gateway(&d, up.port, false);
    let before = avail(&gw.gate);
    assert!(status_line(&request(gw.port, "/v1/nousage")).contains("200"));
    let st = gw.gate.status();
    assert_eq!(st.caps[0].unmetered_requests, 1);
    assert_eq!(st.caps[0].avail_micros, before, "cost unknown: not charged");
}

#[test]
fn a_failing_gate_says_it_is_not_holding_and_an_idle_one_does_not() {
    let missing = CapGate::new(std::path::Path::new("/nonexistent/tethra/vault.db"));
    missing.refresh(&providers());
    assert!(missing.status().failing_open);
    let plain = dev();
    let gate = CapGate::new(&plain.paths.db_path());
    gate.refresh(&providers());
    let st = gate.status();
    assert!(st.inactive_reason.unwrap().contains("not in a mesh"));
    assert!(!st.failing_open, "nothing to enforce is not a failure");
    let (d, _) = capped(USD, false);
    let gate = CapGate::new(&d.paths.db_path());
    gate.refresh(&providers());
    assert!(!gate.status().failing_open);
    let stale =
        CapGate::new(&d.paths.db_path()).with_stale_after_for_test(Duration::from_millis(1));
    stale.refresh(&providers());
    std::thread::sleep(Duration::from_millis(5));
    assert!(stale.status().failing_open);
}

#[test]
fn a_charge_moving_into_the_database_never_drops_out_under_a_published_floor() {
    let (d, p) = capped(100 * USD, true);
    // This device published $10 used while its rollup shows only $5 (an
    // unbound project's spend, say).
    let keys = d.v.mesh_keys().unwrap();
    let cap = caps::resolve(&store(&d), "app").unwrap();
    let month = caps::period::month_of(SystemClock.now_ms());
    store(&d)
        .mint(
            keys.signing_key(),
            Draft::of(
                &api_tracker_core::mesh::kinds::CapUsed {
                    cap,
                    month,
                    epoch: 0,
                    used_micros: 10 * USD,
                },
                HlcPolicy::Now,
            ),
        )
        .unwrap();
    let day = api_tracker_core::mesh::kinds::Day::from_unix_ms(SystemClock.now_ms()).to_string();
    d.v.connection()
        .execute(
            "INSERT INTO gateway_usage_daily (day, provider_id, project_id, model, request_count,
                 usage_event_count, estimated_cost_micros, updated_at, split_known)
             VALUES (?1, 'openai', ?2, 'old', 1, 1, ?3, 'x', 1)",
            rusqlite::params![day, d.app, (5 * USD) as i64],
        )
        .unwrap();
    let _ = p;
    let up = upstream();
    let gw = gateway(&d, up.port, false);
    assert_eq!(avail(&gw.gate), 90 * USD as i64, "the published floor");
    request(gw.port, "/v1/big");
    let in_memory = avail(&gw.gate);
    wait_for("the writer", || persisted_cost(&d) > 5 * USD);
    gw.gate.refresh(&providers());
    assert_eq!(
        avail(&gw.gate),
        in_memory,
        "persisting a charge changes nothing"
    );
}
