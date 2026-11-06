//! The node runtime over real sockets on 127.0.0.1 (Increment 05): nodes
//! converge on their own, find each other by gossip, back off from dead
//! peers, survive a partition, stop when their session ends (dropping their
//! keys), run one per data directory, and answer the control channel.

mod common;

use api_tracker_core::mesh::clock::{Clock, ManualClock, SystemClock};
use api_tracker_core::mesh::peers::{backoff_ms, rfc3339_to_ms, PeerSource};
use api_tracker_mesh::instance::{self, Request, Response};
use api_tracker_mesh::runtime::{Never, SessionAlive, StopFlag, StopReason};
use common::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn sys() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

fn addr_of(n: &api_tracker_mesh::runtime::RunningNode) -> String {
    n.listen_addrs()[0].to_string()
}

fn peer_row(dev: &Dev, addr: &str) -> Option<api_tracker_core::mesh::peers::PeerRow> {
    dev.vault
        .mesh_peers()
        .unwrap()
        .into_iter()
        .find(|r| r.addr == addr)
}

#[test]
fn three_nodes_converge_on_their_own_and_gossip_lets_c_find_a() {
    let a = genesis("dev-a");
    let na = run_node(&a, node_config(200), sys(), Box::new(Never));
    // Each node has published its address (its first round) before another
    // device pairs through it.
    wait_for(10, || na.status().rounds >= 1, "A's first round");
    let b = vault();
    join_via(&a, &addr_of(&na), &b, "dev-b");
    let nb = run_node(&b, node_config(200), sys(), Box::new(Never));
    let a_addr = addr_of(&na);
    wait_for(
        10,
        || peer_row(&b, &a_addr).is_some_and(|r| r.last_success_at.is_some()),
        "B's first exchange with A",
    );
    // C pairs through B. Its only peer is the invite's address (B's); A it
    // must learn from the device.info items it replicates.
    let c = vault();
    join_via(&b, &addr_of(&nb), &c, "dev-c");
    let nc = run_node(&c, node_config(200), sys(), Box::new(Never));
    let c_peers = c.vault.mesh_peers().unwrap();
    assert_eq!(c_peers.len(), 1, "{c_peers:?}");
    assert_eq!(c_peers[0].addr, addr_of(&nb));
    assert_eq!(c_peers[0].device_id, Some(device_id(&b)));

    // No manual exchange from here on: every device renames itself and
    // every other device sees it.
    a.vault.mesh_device_rename("alpha").unwrap();
    b.vault.mesh_device_rename("bravo").unwrap();
    c.vault.mesh_device_rename("charlie").unwrap();
    for (seer, of, name) in [
        (&b, &a, "alpha"),
        (&c, &a, "alpha"),
        (&a, &b, "bravo"),
        (&c, &b, "bravo"),
        (&a, &c, "charlie"),
        (&b, &c, "charlie"),
    ] {
        wait_for(
            20,
            || name_seen_by(seer, of).as_deref() == Some(name),
            &format!("{name} to replicate"),
        );
    }
    // C reached A directly, at the address A published (gossip).
    wait_for(
        10,
        || {
            peer_row(&c, &a_addr).is_some_and(|r| {
                r.source == PeerSource::Gossip
                    && r.last_success_at.is_some()
                    && r.device_id == Some(device_id(&a))
            })
        },
        "C to exchange with A at its gossiped address",
    );
    for n in [na, nb, nc] {
        n.stop();
        let r = n.wait();
        assert_eq!(r.reason, StopReason::Requested);
        assert!(r.keys_dropped);
    }
}

#[test]
fn an_unreachable_peer_is_retried_with_exponential_backoff() {
    let a = genesis("dev-a");
    // A port nothing listens on: bound, then released.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    a.vault.mesh_peer_add(&dead).unwrap();
    let clock = Arc::new(ManualClock::new(1_800_000_000_000));
    let n = run_node(&a, node_config(1_000), clock.clone(), Box::new(Never));
    let mut attempts: Vec<u64> = Vec::new();
    let mut last_failures = 0;
    let mut rounds = n.status().rounds;
    // About 5 minutes of node time in 4-second steps: one round per step.
    for _ in 0..80 {
        clock.advance(4_000);
        wait_for(10, || n.status().rounds > rounds, "the next round");
        rounds = n.status().rounds;
        let row = peer_row(&a, &dead).unwrap();
        if row.failures > last_failures {
            attempts.push(rfc3339_to_ms(row.last_attempt_at.as_deref().unwrap()));
            last_failures = row.failures;
        }
    }
    assert!(attempts.len() >= 5, "{attempts:?}");
    for (k, w) in attempts.windows(2).enumerate() {
        let gap = w[1] - w[0];
        let base = backoff_ms(u32::try_from(k).unwrap() + 1);
        assert!(
            gap >= base * 8 / 10 && gap <= base * 12 / 10 + 4_000,
            "attempt {k}: gap {gap} ms for a backoff of {base} ms ({attempts:?})"
        );
    }
    let row = peer_row(&a, &dead).unwrap();
    assert!(row.unreachable_since.is_some());
    assert_eq!(row.last_error.as_deref(), Some("connection failed"));
    n.stop();
    assert!(n.wait().keys_dropped);
}

/// A TCP forwarder the test can cut: while blocked it drops every
/// connection, so the two nodes behind it are partitioned.
struct Link {
    addr: SocketAddr,
    blocked: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl Link {
    fn to(target: SocketAddr) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        let blocked = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (b, s) = (blocked.clone(), stop.clone());
        std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                let Ok((inbound, _)) = l.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                if b.load(Ordering::SeqCst) {
                    continue;
                }
                let _ = inbound.set_nonblocking(false);
                let Ok(outbound) = TcpStream::connect(target) else {
                    continue;
                };
                for (mut from, mut to) in [
                    (inbound.try_clone().unwrap(), outbound.try_clone().unwrap()),
                    (outbound, inbound),
                ] {
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 16 * 1024];
                        loop {
                            match from.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if to.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = to.shutdown(std::net::Shutdown::Both);
                    });
                }
            }
        });
        Self {
            addr,
            blocked,
            stop,
        }
    }

    fn set_blocked(&self, b: bool) {
        self.blocked.store(b, Ordering::SeqCst);
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[test]
fn partitioned_nodes_diverge_and_converge_after_the_partition_heals() {
    let a = genesis("dev-a");
    let b = vault();
    // Pair first, over a plain accept loop.
    {
        let server = start(&a);
        join_via(&a, &server.addr_string(), &b, "dev-b");
    }
    // Each node is reachable only through its link, and publishes only the
    // link's address, so gossip cannot route around the partition.
    let mut ca = node_config(200);
    let mut cb = node_config(200);
    let reserve = |c: &mut api_tracker_mesh::runtime::NodeConfig| {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        c.listen = vec![addr];
        addr
    };
    let a_real = reserve(&mut ca);
    let b_real = reserve(&mut cb);
    let link_a = Link::to(a_real);
    let link_b = Link::to(b_real);
    ca.advertise = vec![link_a.addr.to_string()];
    cb.advertise = vec![link_b.addr.to_string()];
    b.vault.mesh_peer_add(&link_a.addr.to_string()).unwrap();
    let na = run_node(&a, ca, sys(), Box::new(Never));
    let nb = run_node(&b, cb, sys(), Box::new(Never));
    a.vault.mesh_device_rename("a-before").unwrap();
    wait_for(
        20,
        || name_seen_by(&b, &a).as_deref() == Some("a-before"),
        "the first rename",
    );
    link_a.set_blocked(true);
    link_b.set_blocked(true);
    a.vault.mesh_device_rename("a-during").unwrap();
    b.vault.mesh_device_rename("b-during").unwrap();
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(name_seen_by(&b, &a).as_deref(), Some("a-before"));
    assert_ne!(name_seen_by(&a, &b).as_deref(), Some("b-during"));
    link_a.set_blocked(false);
    link_b.set_blocked(false);
    wait_for(
        30,
        || {
            name_seen_by(&b, &a).as_deref() == Some("a-during")
                && name_seen_by(&a, &b).as_deref() == Some("b-during")
        },
        "convergence after the partition heals",
    );
    for n in [na, nb] {
        n.stop();
        assert!(n.wait().keys_dropped);
    }
}

fn write_session(path: &std::path::Path, id: &str, expires_at: &str) {
    std::fs::write(
        path,
        format!(
            "{{\"session_id\":\"{id}\",\"created_at\":\"2026-01-01T00:00:00Z\",\
             \"expires_at\":\"{expires_at}\",\"ttl_minutes\":15,\"payload_b64\":\"AA==\"}}"
        ),
    )
    .unwrap();
}

#[test]
fn a_node_stops_within_an_interval_when_its_session_expires_or_ends_and_drops_its_keys() {
    for expire in [true, false] {
        let a = genesis("dev-a");
        let path = a.paths.session_path();
        write_session(&path, "session-one", "2999-01-01T00:00:00Z");
        let n = run_node(
            &a,
            node_config(2_000),
            sys(),
            Box::new(SessionAlive::new(&path)),
        );
        wait_for(5, || n.status().rounds >= 1, "the first round");
        assert_eq!(
            instance::running_pid(&a.paths.data_dir),
            Some(std::process::id())
        );
        let at = Instant::now();
        if expire {
            write_session(&path, "session-one", "2000-01-01T00:00:00Z");
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        let report = n.wait();
        assert!(at.elapsed() < Duration::from_secs(2), "{:?}", at.elapsed());
        assert_eq!(
            report.reason,
            if expire {
                StopReason::SessionExpired
            } else {
                StopReason::SessionEnded
            }
        );
        // The test hook: every reference to the node, and so to its keys
        // (MeshKeys and MeshVault zeroize on drop), is gone.
        assert!(report.keys_dropped);
        assert!(instance::running_pid(&a.paths.data_dir).is_none());
    }
}

#[test]
fn a_lock_signal_stops_the_node_and_a_new_session_does_too() {
    let a = genesis("dev-a");
    let flag = StopFlag::new(StopReason::Locked);
    let n = run_node(&a, node_config(200), sys(), Box::new(flag.clone()));
    flag.raise();
    let r = n.wait();
    assert_eq!(r.reason, StopReason::Locked);
    assert!(r.keys_dropped);

    let path = a.paths.session_path();
    write_session(&path, "session-one", "2999-01-01T00:00:00Z");
    let n = run_node(
        &a,
        node_config(200),
        sys(),
        Box::new(SessionAlive::new(&path)),
    );
    // `tethra lock` then `tethra unlock`: a different session.
    write_session(&path, "session-two", "2999-01-01T00:00:00Z");
    assert_eq!(n.wait().reason, StopReason::SessionEnded);
}

#[test]
fn only_one_node_runs_per_data_directory() {
    let a = genesis("dev-a");
    let first = run_node(&a, node_config(500), sys(), Box::new(Never));
    let node = api_tracker_mesh::MeshNode::open(&a.vault, sys(), test_limits()).unwrap();
    let err = match api_tracker_mesh::runtime::RunningNode::start(
        node,
        &a.paths.data_dir,
        node_config(500),
        Box::new(Never),
    ) {
        Ok(_) => panic!("a second node started"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("already running"), "{err}");
    first.stop();
    assert!(first.wait().keys_dropped);
    // Once the first stopped, the directory is free again.
    let again = run_node(&a, node_config(500), sys(), Box::new(Never));
    again.stop();
    again.wait();
}

#[test]
fn the_control_channel_answers_status_replicate_now_and_stop_and_refuses_a_wrong_nonce() {
    let a = genesis("dev-a");
    let na = run_node(&a, node_config(60_000), sys(), Box::new(Never));
    let b = vault();
    join_via(&a, &addr_of(&na), &b, "dev-b");
    b.vault.mesh_peer_add(&addr_of(&na)).unwrap();
    let nb = run_node(&b, node_config(60_000), sys(), Box::new(Never));
    let dir = b.paths.data_dir.clone();
    wait_for(5, || nb.status().rounds >= 1, "the first round");

    let wait = Duration::from_secs(5);
    match instance::request(&dir, |nonce| Request::Status { nonce }, wait).unwrap() {
        Response::Status(s) => {
            assert_eq!(s.pid, std::process::id());
            assert_eq!(s.device_id, device_id(&b));
            assert_eq!(s.listen, vec![addr_of(&nb)]);
            assert_eq!(s.advertised, vec![addr_of(&nb)]);
            assert_eq!(s.interval_ms, 60_000);
            assert!(!s.stopping);
        }
        other => panic!("{other:?}"),
    }
    for bad in [String::new(), "0".repeat(32)] {
        match instance::send(&dir, &Request::Status { nonce: bad.clone() }, wait).unwrap() {
            Response::Error { code, .. } => assert_eq!(code, "unauthorized"),
            other => panic!("{other:?}"),
        }
        match instance::send(&dir, &Request::Stop { nonce: bad }, wait).unwrap() {
            Response::Error { code, .. } => assert_eq!(code, "unauthorized"),
            other => panic!("{other:?}"),
        }
    }
    assert!(!nb.status().stopping);

    // The interval is a minute: only replicate-now brings the rename over.
    a.vault.mesh_device_rename("alpha").unwrap();
    match instance::request(
        &dir,
        |nonce| Request::ReplicateNow {
            nonce,
            peer: None,
            repair: false,
        },
        instance::REPLICATE_WAIT,
    )
    .unwrap()
    {
        Response::Replicated { exchanges, .. } => {
            assert_eq!(exchanges.len(), 1, "{exchanges:?}");
            assert!(exchanges[0].error.is_none(), "{exchanges:?}");
            assert_eq!(exchanges[0].device, Some(device_id(&a)));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(name_seen_by(&b, &a).as_deref(), Some("alpha"));

    assert!(instance::stop(&dir).unwrap());
    let r = nb.wait();
    assert_eq!(r.reason, StopReason::Requested);
    assert!(r.keys_dropped);
    assert!(instance::read_nonce(&dir).is_none());
    na.stop();
    na.wait();
}

#[test]
fn a_node_publishes_its_listen_address_and_the_other_dials_it() {
    let a = genesis("dev-a");
    let na = run_node(&a, node_config(200), sys(), Box::new(Never));
    let b = vault();
    join_via(&a, &addr_of(&na), &b, "dev-b");
    // Joining made the invite's address B's first peer.
    let rows = b.vault.mesh_peers().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].addr.as_str(), rows[0].source, rows[0].device_id),
        (
            addr_of(&na).as_str(),
            PeerSource::Manual,
            Some(device_id(&a))
        )
    );
    let nb = run_node(&b, node_config(200), sys(), Box::new(Never));
    // B publishes its listen address in device.info; A learns it by gossip
    // and dials it, though nobody told A about B's address.
    let b_addr = addr_of(&nb);
    wait_for(
        20,
        || {
            peer_row(&a, &b_addr).is_some_and(|r| {
                r.source == PeerSource::Gossip
                    && r.last_success_at.is_some()
                    && r.device_id == Some(device_id(&b))
            })
        },
        "A to dial B at its published address",
    );
    // The lag record of the last exchange is there, and converged.
    let store = a.vault.mesh_open_store().unwrap();
    let hellos = api_tracker_core::mesh::peers::hello_records(store.connection()).unwrap();
    let rec = &hellos[&device_id(&b)];
    let lag = api_tracker_core::mesh::peers::lag(
        rec,
        api_tracker_core::mesh::store::MeshStore::vv(&store),
    );
    assert!(lag.completed);
    drop(store);
    for n in [na, nb] {
        n.stop();
        assert!(n.wait().keys_dropped);
    }
}
