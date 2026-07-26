//! TEMPORARY probe (delete me): can two Service::start calls race past the
//! instance_is_live check and both come up?

mod common;
use common::*;

use api_tracker_gateway::control;
use api_tracker_gateway::service::Service;
use std::sync::{Arc, Barrier};

#[cfg(unix)]
#[test]
fn probe_two_racing_service_starts() {
    for attempt in 0..20 {
        let dir = tempfile::tempdir().unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _db = test_db(dir.path());
        let barrier = Arc::new(Barrier::new(2));
        let d1 = dir.path().to_path_buf();
        let d2 = dir.path().to_path_buf();
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let t1 = std::thread::spawn(move || {
            b1.wait();
            Service::start(&d1, 0)
        });
        let t2 = std::thread::spawn(move || {
            b2.wait();
            Service::start(&d2, 0)
        });
        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();
        match (r1, r2) {
            (Ok(a), Ok(b)) => {
                eprintln!("attempt {attempt}: BOTH STARTED");
                eprintln!(
                    "  a: port={} control_err={:?}",
                    a.port(),
                    a.control_unavailable()
                );
                eprintln!(
                    "  b: port={} control_err={:?}",
                    b.port(),
                    b.control_unavailable()
                );
                // Which one owns the socket? Try a Status call with the
                // on-disk nonce (what the CLI would do).
                let nonce = control::read_nonce(dir.path()).unwrap().to_string();
                let resp = control::send(dir.path(), &control::Request::Status { nonce }).unwrap();
                eprintln!("  CLI status with on-disk nonce -> {resp:?}");
                // Now stop the degraded loser first and see what survives.
                let (mut winner, mut loser) = if a.control_unavailable().is_some() {
                    (b, a)
                } else {
                    (a, b)
                };
                loser.stop();
                let nonce_file = dir.path().join(control::NONCE_NAME);
                let pid_file = dir.path().join(control::PID_NAME);
                eprintln!(
                    "  after loser.stop(): nonce exists={} pid exists={} winner socket live={}",
                    nonce_file.exists(),
                    pid_file.exists(),
                    control::instance_is_live(dir.path())
                );
                winner.stop();
                panic!("RACE REPRODUCED on attempt {attempt} (see stderr)");
            }
            (a, b) => {
                let ok = |r: &api_tracker_core::error::Result<Service>| match r {
                    Ok(s) => format!(
                        "ok(port={}, control_err={:?})",
                        s.port(),
                        s.control_unavailable()
                    ),
                    Err(e) => format!("err({e})"),
                };
                eprintln!("attempt {attempt}: serialized: {} / {}", ok(&a), ok(&b));
                drop(a);
                drop(b);
            }
        }
    }
    eprintln!("race not reproduced in 20 attempts");
}
