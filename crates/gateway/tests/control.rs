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
