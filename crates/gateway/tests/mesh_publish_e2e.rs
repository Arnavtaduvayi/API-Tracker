//! Gateway → mesh usage, end to end (Increment 06): requests through the real
//! gateway and its writer land in `gateway_usage_daily` with the honesty split
//! (migration v23); the mesh publisher turns them into counters; a second
//! device receives them over the sans-IO session and reports them labelled
//! with the first device. Core only: the gateway never depends on
//! `api-tracker-mesh`, and pairing here uses core's own steps.

mod common;

use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::membership::{self, ExchangeRecord, PendingIdentity};
use api_tracker_core::mesh::proto::{Action, Frame, Limits, Session};
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::usage::UsageFilter;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, NewProject, UnlockedVault, VaultPaths};
use api_tracker_gateway::forward::Gateway;
use api_tracker_gateway::server::{self, Listener};
use api_tracker_gateway::writer::Writer;
use common::*;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

const PW: &str = "mesh-e2e-master-password-1";

/// model, request_count, usage_event_count, unpriced, unextracted, split_known
type DailyRow = (String, i64, i64, i64, i64, i64);

fn new_vault() -> (tempfile::TempDir, VaultPaths, UnlockedVault, String) {
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
    (dir, paths, v, app)
}

fn json_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// One response per path: priced (a model with bundled pricing), unpriced
/// (a model nothing prices), and one that reports no usage.
fn upstream() -> MockUpstream {
    MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        let text = String::from_utf8_lossy(&head).to_string();
        requests.lock().unwrap().push(head);
        let body = if text.contains("/v1/priced") {
            r#"{"model":"gpt-4o","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}"#
        } else if text.contains("/v1/unpriced") {
            r#"{"model":"no-such-model-x9","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#
        } else {
            r#"{"model":"gpt-4o","choices":[]}"#
        };
        let _ = sock.write_all(json_response(body).as_bytes());
        let _ = sock.flush();
    })
}

/// The gateway with its writer on `db_path`, `project` linked to the route.
fn gateway(db_path: &std::path::Path, upstream_port: u16, project: &str) -> (Writer, u16) {
    let writer = Writer::start(db_path, "boot-mesh".into());
    let mut table = api_tracker_gateway::routes::RouteTable::default();
    table.insert_for_test(api_tracker_gateway::routes::Route {
        prefix: "openai".into(),
        provider_id: "openai".into(),
        target: api_tracker_gateway::routes::RouteTarget::Ready(
            api_tracker_gateway::routes::UpstreamOrigin {
                host: "127.0.0.1".into(),
                port: upstream_port,
            },
        ),
        custom: false,
        usage_shape: "openai".into(),
    });
    table.insert_link_for_test(api_tracker_gateway::routes::LinkInfo {
        project_id: project.into(),
        route_prefix: "openai".into(),
        link_slug: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
    });
    let routes = Arc::new(api_tracker_gateway::routes::RouteState::from_table_for_test(table));
    let listener = Listener::bind(0).unwrap();
    let port = listener.port();
    let mut gw = Gateway::new(routes, writer.sink(), port);
    gw.connector = Arc::new(api_tracker_gateway::upstream::InsecurePlainConnectorForTests);
    std::thread::spawn(move || server::serve_with_taps(gw, listener, server::usage_tap_factory()));
    (writer, port)
}

fn request(port: u16, path: &str) {
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let req = format!(
        "POST /p/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/openai{path} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\nAuthorization: Bearer {FAKE_KEY}\r\n\
         Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    c.write_all(req.as_bytes()).unwrap();
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
}

fn exchange(a: &mut SqliteStore, b: &mut SqliteStore) {
    let mut sa = Session::new(Limits::default(), Some(b.self_id()));
    let mut sb = Session::new(Limits::default(), Some(a.self_id()));
    let (mut to_a, mut to_b): (Vec<Frame>, Vec<Frame>) = (Vec::new(), Vec::new());
    let route = |acts: Vec<Action>, out: &mut Vec<Frame>, s: &mut SqliteStore| {
        for act in acts {
            match act {
                Action::Send(f) => out.push(f),
                Action::Commit(batch) => {
                    s.commit(batch).unwrap();
                }
                _ => {}
            }
        }
    };
    let acts = sa.start(&*a);
    route(acts, &mut to_b, a);
    let acts = sb.start(&*b);
    route(acts, &mut to_a, b);
    for _ in 0..1000 {
        if to_a.is_empty() && to_b.is_empty() {
            break;
        }
        for f in std::mem::take(&mut to_b) {
            let acts = sb.on_frame(f, &*b);
            route(acts, &mut to_a, b);
        }
        for f in std::mem::take(&mut to_a) {
            let acts = sa.on_frame(f, &*a);
            route(acts, &mut to_b, a);
        }
    }
}

#[test]
fn gateway_usage_reaches_a_paired_device_split_and_labelled() {
    let (_da, _pa, a, a_app) = new_vault();
    let (_db, _pb, b, b_app) = new_vault();
    a.mesh_init("laptop").unwrap();
    // B joins A's mesh with core's pairing steps.
    let inv = a.mesh_invite_create(&SecretString::from(PW), None).unwrap();
    let pending = PendingIdentity::generate("desktop").unwrap();
    let req = pending.request();
    let now = SystemClock.now_ms();
    let access = a
        .mesh_vault()
        .access_keys(a.connection(), now)
        .unwrap()
        .current;
    let keys = a.mesh_keys().unwrap();
    let accept = membership::accept_pairing(
        &mut a.mesh_open_store().unwrap(),
        keys.signing_key(),
        &inv.token.hash(),
        &req,
        &req.noise_pub,
        &access,
    )
    .unwrap();
    b.mesh_join(&pending, &accept).unwrap();
    let (p, _) = a.mesh_project_share(&a_app).unwrap();

    // Real traffic through the gateway into A's database.
    let up = upstream();
    let a_db = _pa.db_path();
    let (writer, port) = gateway(&a_db, up.port, &a_app);
    for path in ["/v1/priced", "/v1/priced", "/v1/unpriced", "/v1/none"] {
        request(port, path);
    }
    assert!(writer.sink().flush(Duration::from_secs(10)));
    // Each class landed in its column (the writer's split, v23).
    let conn = api_tracker_core::db::open(&a_db).unwrap();
    let rows: Vec<DailyRow> = conn
        .prepare(
            "SELECT model, request_count, usage_event_count, unpriced_requests,
                    unextracted_requests, split_known
             FROM gateway_usage_daily WHERE project_id = ?1 ORDER BY model",
        )
        .unwrap()
        .query_map([&a_app], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let sum = |f: fn(&DailyRow) -> i64| rows.iter().map(f).sum::<i64>();
    assert!(rows.iter().all(|r| r.5 == 1), "{rows:?}");
    let requests = sum(|r| r.1);
    let unpriced = sum(|r| r.3);
    let unextracted = sum(|r| r.4);
    assert_eq!(unpriced, 1, "{rows:?}");
    assert_eq!(unextracted, requests - sum(|r| r.2), "{rows:?}");
    assert_eq!(unextracted, 1, "the response without usage: {rows:?}");
    let priced = requests - unpriced - unextracted;
    assert_eq!(priced, 2, "{rows:?}");

    // Publish on A, replicate to B, bind on B, read B's report.
    let r = a.mesh_publish().unwrap();
    assert!(r.minted >= 2, "{r:?}");
    let (mut sa, mut sb) = (a.mesh_open_store().unwrap(), b.mesh_open_store().unwrap());
    exchange(&mut sa, &mut sb);
    membership::log_exchange(
        sb.connection(),
        &ExchangeRecord {
            peer_device: Some(sa.self_id()),
            direction: "inbound",
            items_in: 0,
            items_out: 0,
            result: "ok",
            error: None,
        },
    )
    .unwrap();
    b.mesh_project_bind(&p.to_hex(), &b_app).unwrap();
    let report = b.mesh_usage(&UsageFilter::default()).unwrap();
    let laptop = report.projects[0]
        .devices
        .iter()
        .find(|d| d.device_name.as_deref() == Some("laptop"))
        .expect("A's figures on B");
    assert!(!laptop.is_self && laptop.as_of.is_some() && !laptop.stale);
    let t = laptop.totals;
    assert_eq!(t.requests, requests as u64);
    assert_eq!(t.priced_requests, 2);
    assert_eq!(t.unpriced_requests, 1);
    assert_eq!(t.unextracted_requests, unextracted as u64);
    assert!(t.estimated_cost_micros > 0, "gpt-4o has a bundled price");
    assert_eq!(laptop.split_unknown_requests, 0);
}
