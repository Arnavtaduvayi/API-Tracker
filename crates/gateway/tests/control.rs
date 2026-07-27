//! Control-plane tests (TEST_PLAN §3 control channel, §5 key lifecycle).
//!
//! The property under test: privileged operations are reachable ONLY over the
//! authenticated local channel, never over the forwarding port, and the key
//! can be pushed but never read back.

mod common;

use common::*;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_tracker_core::secret::SecretBytes;
use api_tracker_gateway::control::{
    self, ControlServer, ControlTarget, Request, Response, Status, NONCE_NAME, PID_NAME,
    SOCKET_NAME,
};

#[derive(Default)]
struct TestTarget {
    key: Mutex<Option<Vec<u8>>>,
    reloads: Mutex<u32>,
    paused: AtomicBool,
    stopped: AtomicBool,
    locks: Mutex<Vec<Option<u32>>>,
    unlocks: Mutex<u32>,
    route_key: Mutex<Option<Vec<u8>>>,
}

impl ControlTarget for TestTarget {
    fn status(&self) -> Status {
        Status {
            version: "test".into(),
            port: 49999,
            routes: 2,
            routes_unavailable: 1,
            queue_depth: 3,
            dropped_events: 4,
            matching_key_present: self.key.lock().unwrap().is_some(),
            recording_paused: self.paused.load(Ordering::Relaxed),
            recording_degraded: false,
            last_observation_at: Some("2026-07-26T00:00:00Z".into()),
            ..Status::default()
        }
    }
    fn push_key(&self, key: SecretBytes) -> api_tracker_core::error::Result<()> {
        *self.key.lock().unwrap() = Some(key.expose().to_vec());
        Ok(())
    }
    fn revoke_key(&self) {
        *self.key.lock().unwrap() = None;
    }
    fn set_route_key(&self, key: Option<SecretBytes>) {
        *self.route_key.lock().unwrap() = key.map(|k| k.expose().to_vec());
    }
    fn vault_locked(&self, ttl_minutes: Option<u32>) {
        self.locks.lock().unwrap().push(ttl_minutes);
    }
    fn vault_unlocked(&self) {
        *self.unlocks.lock().unwrap() += 1;
    }
    fn reload_routes(&self) {
        *self.reloads.lock().unwrap() += 1;
    }
    fn set_recording_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }
    fn shutdown(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
}

const KEY_HEX: &str = "3c1f0a5b8e2d47690a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071";

struct Running {
    dir: tempfile::TempDir,
    nonce: String,
    target: Arc<TestTarget>,
    server: Option<ControlServer>,
}

impl Running {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        // The data directory is 0700, exactly as the vault's own is.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let nonce = control::write_nonce(dir.path()).unwrap().to_string();
        let target = Arc::new(TestTarget::default());
        control::write_pid_file(dir.path()).unwrap();
        let server = ControlServer::start(
            dir.path(),
            nonce.clone(),
            target.clone() as Arc<dyn ControlTarget>,
        )
        .unwrap();
        Self {
            dir,
            nonce,
            target,
            server: Some(server),
        }
    }

    fn send(&self, request: &Request) -> Response {
        control::send(self.dir.path(), request).unwrap()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut s) = self.server.take() {
            s.stop();
        }
        control::remove_pid_file(self.dir.path());
    }
}

#[cfg(unix)]
#[test]
fn the_control_socket_is_owner_only_inside_an_owner_only_directory() {
    use std::os::unix::fs::PermissionsExt;
    let gw = Running::start();
    let sock = gw.dir.path().join(SOCKET_NAME);
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "the control socket must be owner-only: connecting to a unix socket \
         requires write permission on the inode, which is the same-uid gate"
    );
    let dir_mode = std::fs::metadata(gw.dir.path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o077, 0, "the data directory must be owner-only");

    // The nonce and pid files are equally private.
    for name in [NONCE_NAME, PID_NAME] {
        let m = std::fs::metadata(gw.dir.path().join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(m & 0o777, 0o600, "{name} must be owner-only");
    }
}

#[cfg(unix)]
#[test]
fn health_works_without_the_nonce_but_everything_privileged_needs_it() {
    let gw = Running::start();
    assert_eq!(
        gw.send(&Request::Health),
        Response::Health { healthy: true }
    );
    match gw.send(&Request::Version) {
        Response::Version { version } => assert!(!version.is_empty()),
        other => panic!("got {other:?}"),
    }

    let wrong = "00000000000000000000000000000000".to_string();
    for req in [
        Request::Status {
            nonce: wrong.clone(),
        },
        Request::PushKey {
            nonce: wrong.clone(),
            key_hex: KEY_HEX.into(),
        },
        Request::RevokeKey {
            nonce: wrong.clone(),
        },
        Request::ReloadRoutes {
            nonce: wrong.clone(),
        },
        Request::PauseRecording {
            nonce: wrong.clone(),
        },
        Request::ResumeRecording {
            nonce: wrong.clone(),
        },
        Request::Shutdown { nonce: wrong },
    ] {
        match gw.send(&req) {
            Response::Error { code, .. } => assert_eq!(code, "unauthorized"),
            other => panic!("{req:?} must be refused over the socket too, got {other:?}"),
        }
    }
    assert!(gw.target.key.lock().unwrap().is_none());
    assert_eq!(*gw.target.reloads.lock().unwrap(), 0);
    assert!(!gw.target.stopped.load(Ordering::Relaxed));
}

#[cfg(unix)]
#[test]
fn the_key_is_pushable_and_revocable_but_never_readable_back() {
    let gw = Running::start();
    assert_eq!(
        gw.send(&Request::PushKey {
            nonce: gw.nonce.clone(),
            key_hex: KEY_HEX.into(),
        }),
        Response::Ok
    );
    assert_eq!(gw.target.key.lock().unwrap().as_ref().unwrap().len(), 32);

    // Status reports presence; the wire bytes never contain the key.
    let raw = {
        use std::io::{BufRead, BufReader};
        let mut stream =
            std::os::unix::net::UnixStream::connect(gw.dir.path().join(SOCKET_NAME)).unwrap();
        let mut line = serde_json::to_string(&Request::Status {
            nonce: gw.nonce.clone(),
        })
        .unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut out = String::new();
        reader.read_line(&mut out).unwrap();
        out
    };
    assert!(raw.contains("\"matching_key_present\":true"));
    assert!(!raw.contains(KEY_HEX), "the key must never be echoed back");
    assert!(!raw.contains("3c1f0a5b"), "not even a prefix of it");

    assert_eq!(
        gw.send(&Request::RevokeKey {
            nonce: gw.nonce.clone()
        }),
        Response::Ok
    );
    assert!(gw.target.key.lock().unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn a_second_instance_refuses_to_take_over_a_live_socket() {
    let gw = Running::start();
    assert!(control::instance_is_live(gw.dir.path()));
    let second = ControlServer::start(
        gw.dir.path(),
        gw.nonce.clone(),
        Arc::new(TestTarget::default()) as Arc<dyn ControlTarget>,
    );
    assert!(
        second.is_err(),
        "a second gateway must not silently take over a live data directory"
    );
    let err = format!("{}", second.err().unwrap());
    assert!(err.contains("already running"), "got: {err}");
}

#[cfg(unix)]
#[test]
fn a_stale_socket_and_pid_from_a_dead_instance_do_not_block_startup() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Leave behind exactly what a SIGKILLed instance leaves: a socket file
    // nobody is listening on, and a pid file naming a dead (or recycled) pid.
    std::fs::write(dir.path().join(SOCKET_NAME), b"stale").unwrap();
    std::fs::write(dir.path().join(PID_NAME), b"999999").unwrap();
    assert!(
        !control::instance_is_live(dir.path()),
        "liveness is decided by the SOCKET, not by a pid number that may be recycled"
    );

    let nonce = control::write_nonce(dir.path()).unwrap().to_string();
    let mut server = ControlServer::start(
        dir.path(),
        nonce.clone(),
        Arc::new(TestTarget::default()) as Arc<dyn ControlTarget>,
    )
    .expect("a stale socket must not prevent startup");
    assert_eq!(
        control::send(dir.path(), &Request::Health).unwrap(),
        Response::Health { healthy: true }
    );
    server.stop();
}

#[cfg(unix)]
#[test]
fn a_symlinked_socket_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::os::unix::fs::symlink(
        elsewhere.path().join("evil.sock"),
        dir.path().join(SOCKET_NAME),
    )
    .unwrap();
    let err = ControlServer::start(
        dir.path(),
        "nonce".into(),
        Arc::new(TestTarget::default()) as Arc<dyn ControlTarget>,
    )
    .unwrap_err();
    assert!(
        format!("{err}").contains("symlink"),
        "a planted symlink must be refused, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn a_loosened_socket_mode_stops_the_channel_rather_than_widening_it() {
    use std::os::unix::fs::PermissionsExt;
    let gw = Running::start();
    let sock = gw.dir.path().join(SOCKET_NAME);
    // Health works while the permissions are correct.
    assert_eq!(
        gw.send(&Request::Health),
        Response::Health { healthy: true }
    );

    // Someone loosens the socket. The channel must stop answering.
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();
    let result = control::send(gw.dir.path(), &Request::Health);
    assert!(
        result.is_err(),
        "a world-writable control socket must stop being served, not keep answering"
    );
}

#[cfg(unix)]
#[test]
fn control_operations_take_effect_and_report_truthfully() {
    let gw = Running::start();
    assert_eq!(
        gw.send(&Request::ReloadRoutes {
            nonce: gw.nonce.clone()
        }),
        Response::Ok
    );
    assert_eq!(*gw.target.reloads.lock().unwrap(), 1);

    assert_eq!(
        gw.send(&Request::PauseRecording {
            nonce: gw.nonce.clone()
        }),
        Response::Ok
    );
    let status = match gw.send(&Request::Status {
        nonce: gw.nonce.clone(),
    }) {
        Response::Status(s) => *s,
        other => panic!("got {other:?}"),
    };
    assert!(status.recording_paused, "status reports the pause honestly");
    assert_eq!(status.routes, 2);
    assert_eq!(
        status.routes_unavailable, 1,
        "unforwardable routes are visible"
    );
    assert_eq!(status.queue_depth, 3);
    assert_eq!(
        status.dropped_events, 4,
        "a coverage gap is surfaced, not hidden"
    );
    assert!(status.last_observation_at.is_some());

    assert_eq!(
        gw.send(&Request::ResumeRecording {
            nonce: gw.nonce.clone()
        }),
        Response::Ok
    );
    assert_eq!(
        gw.send(&Request::Shutdown {
            nonce: gw.nonce.clone()
        }),
        Response::Ok
    );
    assert!(gw.target.stopped.load(Ordering::Relaxed));
}

/// The forwarding port must expose NO control surface at all.
#[test]
fn the_forwarding_port_offers_no_control_operations() {
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        0,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let auth = gw.authority();
    // Every plausible control path on the TCP listener must 404 exactly like
    // any other unknown route — it must not even acknowledge existing.
    let mut responses = Vec::new();
    for path in [
        "/_tethra/key",
        "/_tethra/control",
        "/_tethra/status",
        "/control/push_key",
        "/gateway/key",
    ] {
        let mut c = gw.connect();
        send(
            &mut c,
            &format!("POST {path} HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 0\r\n\r\n"),
        );
        let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        assert!(
            resp.starts_with("HTTP/1.1 404"),
            "{path} must 404 on the forwarding port, got {resp:?}"
        );
        responses.push(resp);
    }
    // And they are indistinguishable from any other unknown route.
    assert!(
        responses.windows(2).all(|w| w[0] == w[1]),
        "control paths must not be distinguishable from unknown routes"
    );
    assert_eq!(up.request_count(), 0);
}

#[test]
fn the_matching_key_never_crosses_tcp_argv_or_the_environment() {
    // Source-level pin for SI-21, complementing the runtime canary: the
    // forwarding/listener modules must never touch key material, and no
    // module may read a key out of the environment or argv.
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }
    walk(&src, &mut files);
    for file in &files {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        let code: String = std::fs::read_to_string(file)
            .unwrap()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        // No module may source key material from the process environment or
        // command line.
        for pat in [
            "env::var(\"TETHRA_GATEWAY_KEY",
            "env::var(\"GATEWAY_KEY",
            "MATCHING_KEY",
            "FINGERPRINT_KEY",
        ] {
            assert!(
                !code.contains(pat),
                "`{pat}` in {name}: the matching key must arrive ONLY over the \
                 authenticated control channel (SI-21)"
            );
        }
        // The TCP listener and its exchange path must not name the key at all
        // beyond reading the shared slot the control channel populates.
        if name == "server.rs" {
            assert!(
                !code.contains("matching_key") && !code.contains("push_key"),
                "the TCP listener module must not touch key material"
            );
        }
    }
    // The control module is the only place a key is parsed.
    let control = std::fs::read_to_string(src.join("control.rs")).unwrap();
    assert!(control.contains("PushKey"));
    let forward = std::fs::read_to_string(src.join("forward.rs")).unwrap();
    assert!(
        !forward.contains("PushKey"),
        "the forwarding module must not implement key installation"
    );
}

#[cfg(unix)]
#[test]
fn an_oversized_or_garbage_request_is_refused_without_affecting_the_channel() {
    use std::io::{BufRead, BufReader};
    let gw = Running::start();
    // Garbage.
    {
        let mut stream =
            std::os::unix::net::UnixStream::connect(gw.dir.path().join(SOCKET_NAME)).unwrap();
        stream.write_all(b"this is not json\n").unwrap();
        stream.flush().unwrap();
        let mut out = String::new();
        BufReader::new(stream).read_line(&mut out).unwrap();
        assert!(out.contains("invalid_input"), "got {out}");
    }
    // A flood far past the request cap must not wedge the channel.
    {
        let mut stream =
            std::os::unix::net::UnixStream::connect(gw.dir.path().join(SOCKET_NAME)).unwrap();
        let huge = vec![b'a'; control::MAX_REQUEST * 4];
        let _ = stream.write_all(&huge);
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut out = String::new();
        let _ = BufReader::new(stream).read_line(&mut out);
    }
    // The channel still works.
    assert_eq!(
        gw.send(&Request::Health),
        Response::Health { healthy: true }
    );
    std::thread::sleep(Duration::from_millis(10));
}

/// End-to-end: a real assembled Service, driven entirely through the
/// authenticated channel.
#[cfg(unix)]
#[test]
fn a_real_service_is_controllable_end_to_end_over_the_authenticated_channel() {
    use api_tracker_gateway::service::Service;

    let dir = tempfile::tempdir().unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let _db = test_db(dir.path());
    let mut service = Service::start(dir.path(), 0).expect("the service must start");
    let nonce = control::read_nonce(dir.path()).unwrap().to_string();
    let port = service.port();
    assert_ne!(port, 0);

    // Health with no nonce.
    assert_eq!(
        control::send(dir.path(), &Request::Health).unwrap(),
        Response::Health { healthy: true }
    );

    // Status reports the real port and a truthful picture, WITHOUT the vault
    // being unlocked — the lock screen depends on exactly this.
    let status = match control::send(
        dir.path(),
        &Request::Status {
            nonce: nonce.clone(),
        },
    )
    .unwrap()
    {
        Response::Status(s) => *s,
        other => panic!("got {other:?}"),
    };
    assert_eq!(status.port, port);
    assert!(!status.matching_key_present, "no key until one is pushed");
    assert!(!status.recording_paused);
    assert_eq!(status.dropped_events, 0);

    // Push and revoke the key over the channel; presence flips both ways.
    assert_eq!(
        control::send(
            dir.path(),
            &Request::PushKey {
                nonce: nonce.clone(),
                key_hex: KEY_HEX.into(),
            },
        )
        .unwrap(),
        Response::Ok
    );
    assert!(service.gateway().has_matching_key());
    assert_eq!(
        control::send(
            dir.path(),
            &Request::RevokeKey {
                nonce: nonce.clone()
            },
        )
        .unwrap(),
        Response::Ok
    );
    assert!(!service.gateway().has_matching_key());

    // Pause and resume recording; forwarding is untouched either way.
    control::send(
        dir.path(),
        &Request::PauseRecording {
            nonce: nonce.clone(),
        },
    )
    .unwrap();
    assert!(service
        .gateway()
        .recording_paused
        .load(std::sync::atomic::Ordering::Relaxed));
    control::send(
        dir.path(),
        &Request::ResumeRecording {
            nonce: nonce.clone(),
        },
    )
    .unwrap();

    // Reload routes.
    assert_eq!(
        control::send(
            dir.path(),
            &Request::ReloadRoutes {
                nonce: nonce.clone()
            },
        )
        .unwrap(),
        Response::Ok
    );

    // Shutdown over the channel really stops it.
    assert_eq!(
        control::send(dir.path(), &Request::Shutdown { nonce }).unwrap(),
        Response::Ok
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !service.is_stopping() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(service.is_stopping());
    service.stop();

    // Artifacts are cleaned up so a later start is not confused by them.
    assert!(!dir.path().join(SOCKET_NAME).exists());
    assert!(!dir.path().join(PID_NAME).exists());
    assert!(!dir.path().join(NONCE_NAME).exists());
}

#[cfg(unix)]
#[test]
fn a_service_refuses_to_start_twice_against_one_data_directory() {
    use api_tracker_gateway::service::Service;
    let dir = tempfile::tempdir().unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let _db = test_db(dir.path());
    let mut first = Service::start(dir.path(), 0).unwrap();
    let second = Service::start(dir.path(), 0);
    assert!(
        second.is_err(),
        "a duplicate instance must be refused, not silently take over"
    );
    first.stop();
    // After a clean stop, a fresh instance starts normally.
    let mut third = Service::start(dir.path(), 0).expect("start after a clean stop");
    third.stop();
}

// ---------------------------------------------------------------------------
// Matching-key lock lifecycle (ADR 0020, SI-9)
// ---------------------------------------------------------------------------

/// Give the poller thread time to observe an expired retention window.
#[cfg(unix)]
fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
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
fn set_keep_while_locked(db: &std::path::Path, enabled: bool) {
    let conn = open_db(db);
    api_tracker_gateway::store::set_match_while_locked(&conn, enabled).unwrap();
}

/// Push a key into a running service the way the frontends do, over the
/// authenticated channel, and assert it landed.
#[cfg(unix)]
fn push_key_into(data_dir: &std::path::Path) {
    let nonce = control::read_nonce(data_dir).unwrap();
    let response = control::send(
        data_dir,
        &Request::PushKey {
            nonce: nonce.to_string(),
            key_hex: KEY_HEX.into(),
        },
    )
    .unwrap();
    assert_eq!(response, Response::Ok, "the key must install");
}

#[cfg(unix)]
fn status_of(data_dir: &std::path::Path) -> Status {
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

/// THE regression test for the audited blocker: by default, locking the
/// vault drops the resident matching key. Mutation check — deleting the
/// `vault_locked` wiring in `ServiceControl` (or the `notify_vault_locked`
/// call in either frontend's lock path) fails this.
#[cfg(unix)]
#[test]
fn locking_the_vault_revokes_the_resident_matching_key_by_default() {
    use api_tracker_gateway::service::Service;
    let dir = service_dir();
    let _db = test_db(dir.path());
    let mut service = Service::start(dir.path(), 0).unwrap();

    push_key_into(dir.path());
    assert!(
        status_of(dir.path()).matching_key_present,
        "precondition: the key is resident"
    );

    // The frontend-facing helper every lock path calls.
    assert!(
        control::notify_vault_locked(dir.path(), Some(15)),
        "the lock signal must be delivered"
    );

    let after = status_of(dir.path());
    assert!(
        !after.matching_key_present,
        "SI-9: locking the vault must drop the matching key when \
         keep-while-locked is OFF (the shipped default)"
    );
    assert_eq!(
        after.matching_key_deadline_secs, None,
        "a revoked key must not leave a retention window armed"
    );
    service.stop();
}

/// Forwarding is untouched by a lock: the listener keeps serving and the
/// route table is unaffected. (SI-12's lock twin — attribution degrades,
/// forwarding does not.)
#[cfg(unix)]
#[test]
fn forwarding_continues_after_the_lock_revokes_the_key() {
    use api_tracker_gateway::service::Service;
    use std::io::{Read, Write};
    let dir = service_dir();
    let _db = test_db(dir.path());
    let mut service = Service::start(dir.path(), 0).unwrap();
    let port = service.port();

    push_key_into(dir.path());
    assert!(control::notify_vault_locked(dir.path(), None));
    assert!(!status_of(dir.path()).matching_key_present);

    // The listener still answers. No route is registered, so the honest
    // answer is a 404 — what matters is that the port is still served and
    // the connection is not refused.
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        sock,
        "GET /openai/v1/models HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut got = String::new();
    sock.read_to_string(&mut got).unwrap();
    assert!(
        got.starts_with("HTTP/1.1 "),
        "the gateway must keep serving after a vault lock, got: {got:?}"
    );
    assert!(
        !got.starts_with("HTTP/1.1 5"),
        "a lock must not turn forwarding into a server error, got: {got:?}"
    );
    service.stop();
}

/// An unreadable / malformed policy configuration fails TOWARD revocation.
#[cfg(unix)]
#[test]
fn an_unreadable_policy_config_fails_toward_revoking_the_key() {
    use api_tracker_gateway::service::{lock_disposition, LockDisposition};
    let dir = service_dir();

    // No database at all.
    assert_eq!(
        lock_disposition(&dir.path().join("vault.db"), Some(60)),
        LockDisposition::RevokeNow,
        "a missing database must not be read as consent to retain the key"
    );

    // A file that is not a database.
    let junk = dir.path().join("junk.db");
    std::fs::write(&junk, b"this is not a sqlite database").unwrap();
    assert_eq!(
        lock_disposition(&junk, Some(60)),
        LockDisposition::RevokeNow,
        "a malformed database must fail toward revocation"
    );

    // A real database whose toggle is OFF (the default).
    let db = test_db(dir.path());
    assert_eq!(
        lock_disposition(&db, Some(60)),
        LockDisposition::RevokeNow,
        "the toggle defaults OFF, so a lock revokes"
    );
}

/// With the consented toggle ON the key survives the lock — but only inside
/// a bounded window, and the window is visible in status.
#[cfg(unix)]
#[test]
fn keep_while_locked_retains_the_key_within_a_bounded_window() {
    use api_tracker_gateway::service::Service;
    let dir = service_dir();
    let db = test_db(dir.path());
    set_keep_while_locked(&db, true);
    let mut service = Service::start(dir.path(), 0).unwrap();

    push_key_into(dir.path());
    assert!(control::notify_vault_locked(dir.path(), Some(30)));

    let after = status_of(dir.path());
    assert!(
        after.matching_key_present,
        "the consented opt-out must be honored"
    );
    let remaining = after
        .matching_key_deadline_secs
        .expect("retention must be bounded, never indefinite");
    assert!(
        remaining > 0 && remaining <= 30 * 60,
        "the window must be bounded by the requested 30 minutes, got {remaining}s"
    );
    service.stop();
}

/// The TTL is a CAP, not a suggestion: a caller asking for longer than the
/// documented maximum gets the maximum.
#[test]
fn the_retention_request_is_clamped_to_the_documented_cap() {
    use api_tracker_gateway::service::{
        effective_retention_minutes, MATCH_WHILE_LOCKED_TTL_CAP_MINUTES,
    };
    assert_eq!(effective_retention_minutes(Some(15)), 15, "under the cap");
    assert_eq!(
        effective_retention_minutes(Some(100_000)),
        MATCH_WHILE_LOCKED_TTL_CAP_MINUTES,
        "a caller cannot ask for more than the cap"
    );
    assert_eq!(
        effective_retention_minutes(None),
        MATCH_WHILE_LOCKED_TTL_CAP_MINUTES,
        "no stated duration (auto-lock disabled) still expires at the cap"
    );
    assert_eq!(
        effective_retention_minutes(Some(0)),
        MATCH_WHILE_LOCKED_TTL_CAP_MINUTES,
        "auto-lock disabled (0) must not mean 'forever'"
    );
    assert_eq!(
        MATCH_WHILE_LOCKED_TTL_CAP_MINUTES, 480,
        "the documented cap is 8 hours (ADR 0020); changing it is a product \
         decision that must update the ADR and the consent copy"
    );
}

/// When the bounded window expires, the key is actually dropped by the
/// running service — and status says so honestly.
#[cfg(unix)]
#[test]
fn an_expired_keep_while_locked_window_drops_the_key() {
    use api_tracker_gateway::service::Service;
    let dir = service_dir();
    let db = test_db(dir.path());
    set_keep_while_locked(&db, true);
    let mut service = Service::start(dir.path(), 0).unwrap();

    push_key_into(dir.path());
    assert!(control::notify_vault_locked(dir.path(), Some(30)));
    assert!(status_of(dir.path()).matching_key_present);

    // Arm an already-elapsed deadline rather than sleeping 30 minutes.
    service.key_retention().arm_already_expired_for_test();

    assert!(
        wait_until(|| !status_of(dir.path()).matching_key_present),
        "the service must enforce its own retention window"
    );
    let after = status_of(dir.path());
    assert!(
        after.matching_key_expired,
        "expiry must be distinguishable from 'never pushed'"
    );
    assert_eq!(after.matching_key_deadline_secs, None);
    service.stop();
}

/// Unlocking cancels a pending window; a fresh push clears the expired flag.
#[cfg(unix)]
#[test]
fn unlocking_cancels_the_window_and_a_fresh_push_clears_the_expiry() {
    use api_tracker_gateway::service::Service;
    let dir = service_dir();
    let db = test_db(dir.path());
    set_keep_while_locked(&db, true);
    let mut service = Service::start(dir.path(), 0).unwrap();

    push_key_into(dir.path());
    assert!(control::notify_vault_locked(dir.path(), Some(30)));
    assert!(status_of(dir.path()).matching_key_deadline_secs.is_some());

    assert!(control::notify_vault_unlocked(dir.path()));
    let after = status_of(dir.path());
    assert!(
        after.matching_key_deadline_secs.is_none(),
        "a re-authorized session cancels the countdown"
    );
    assert!(
        after.matching_key_present,
        "unlocking must not drop a key the user still wants"
    );

    // Expire it, then re-push: the expired marker must clear.
    service.key_retention().arm_already_expired_for_test();
    assert!(wait_until(|| !status_of(dir.path()).matching_key_present));
    assert!(status_of(dir.path()).matching_key_expired);
    push_key_into(dir.path());
    let after = status_of(dir.path());
    assert!(after.matching_key_present);
    assert!(
        !after.matching_key_expired,
        "a fresh authorization clears the expiry marker"
    );
    service.stop();
}

/// Restart behavior: a service that starts (or restarts) never reconstructs
/// a resident key from anything on disk. Attribution stays off until a
/// vault session pushes it again.
#[cfg(unix)]
#[test]
fn a_restarted_service_never_reconstructs_the_matching_key() {
    use api_tracker_gateway::service::Service;
    let dir = service_dir();
    let db = test_db(dir.path());
    // Even with the consented toggle ON, which is the strongest case for
    // "the user wants matching to persist".
    set_keep_while_locked(&db, true);

    let mut first = Service::start(dir.path(), 0).unwrap();
    push_key_into(dir.path());
    assert!(status_of(dir.path()).matching_key_present);
    first.stop();

    let mut second = Service::start(dir.path(), 0).unwrap();
    let after = status_of(dir.path());
    assert!(
        !after.matching_key_present,
        "a restart must not resurrect the key: nothing persists it, and \
         keep-while-locked bounds residency WITHIN a process, never across one"
    );
    assert_eq!(after.matching_key_deadline_secs, None);
    second.stop();
}

/// Turning the toggle OFF drops a resident key immediately (SI-9
/// "toggle-off"), without waiting for a lock.
#[cfg(unix)]
#[test]
fn disabling_keep_while_locked_drops_the_resident_key_now() {
    use api_tracker_gateway::service::Service;
    let dir = service_dir();
    let db = test_db(dir.path());
    set_keep_while_locked(&db, true);
    let mut service = Service::start(dir.path(), 0).unwrap();
    push_key_into(dir.path());
    assert!(status_of(dir.path()).matching_key_present);

    // What the CLI/desktop toggle-off path does.
    set_keep_while_locked(&db, false);
    assert!(control::send_revoke_key(dir.path()));

    assert!(
        !status_of(dir.path()).matching_key_present,
        "turning the opt-out off must not wait for the next lock"
    );
    service.stop();
}

/// A lock signal that arrives with no key resident is a no-op, not a way to
/// arm a window that would later be honored against a future key.
#[cfg(unix)]
#[test]
fn a_lock_with_no_resident_key_arms_nothing() {
    use api_tracker_gateway::service::Service;
    let dir = service_dir();
    let db = test_db(dir.path());
    set_keep_while_locked(&db, true);
    let mut service = Service::start(dir.path(), 0).unwrap();

    assert!(control::notify_vault_locked(dir.path(), Some(30)));
    let after = status_of(dir.path());
    assert!(!after.matching_key_present);
    assert_eq!(
        after.matching_key_deadline_secs, None,
        "no key, no window — a later push must start from a clean slate"
    );
    service.stop();
}

/// Repeated lock events only ever TIGHTEN the deadline. Otherwise the
/// desktop's 10-second status poll would refresh the window forever while
/// the vault stayed locked, making the bound meaningless.
#[cfg(unix)]
#[test]
fn repeated_lock_signals_never_extend_the_window() {
    use api_tracker_gateway::service::Service;
    let dir = service_dir();
    let db = test_db(dir.path());
    set_keep_while_locked(&db, true);
    let mut service = Service::start(dir.path(), 0).unwrap();
    push_key_into(dir.path());

    assert!(control::notify_vault_locked(dir.path(), Some(5)));
    let first = status_of(dir.path()).matching_key_deadline_secs.unwrap();
    // A later, LONGER request (e.g. a poll that reports the 8-hour cap).
    assert!(control::notify_vault_locked(dir.path(), Some(480)));
    let second = status_of(dir.path()).matching_key_deadline_secs.unwrap();
    assert!(
        second <= first,
        "a repeated lock must not extend the window: {first}s -> {second}s"
    );
    service.stop();
}
