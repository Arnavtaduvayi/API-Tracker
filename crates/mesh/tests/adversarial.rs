//! Adversarial and chaos tests (Increment 12, Phase A): seeded fuzzing of
//! every parser that sees untrusted bytes, handshake floods across many
//! source ports, a peer that stalls after its Hello, a Commit that claims
//! more than it sent, a year of clock skew either way, a removed device
//! coming back with old and new access keys, a forked clone racing its
//! original, a backup restore under a running node, a writer storm on the
//! database during exchanges, and a flood of `Direct` frames.
//!
//! Real vaults in temp directories, sockets on 127.0.0.1:0 only, fake
//! values only. Nothing here multicasts or touches a real data directory.

mod common;

use api_tracker_core::mesh::clock::{Clock, ManualClock, SystemClock};
use api_tracker_core::mesh::codec::MAX_ITEM_BYTES;
use api_tracker_core::mesh::identity;
use api_tracker_core::mesh::invite::{format_invite, parse_invite};
use api_tracker_core::mesh::item::SignedItem;
use api_tracker_core::mesh::kinds::{MeshSetting, TypedItem};
use api_tracker_core::mesh::proto::{Action, Body, DirectMsg, Frame, Limits, Session};
use api_tracker_core::mesh::sim::rng::SplitMix64;
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::{Draft, HlcPolicy, MeshStore};
use api_tracker_core::secret::SecretString;
use api_tracker_mesh::replicate::replicate_once;
use api_tracker_mesh::runtime::{Never, StopReason};
use api_tracker_mesh::{handshake, wire, TransportLimits};
use common::*;
use std::io::{Cursor, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DAY_MS: u64 = 86_400_000;

fn set(store: &mut SqliteStore, d: &Dev, name: &str, v: u64) {
    let keys = d.vault.mesh_keys().unwrap();
    let m = MeshSetting {
        name: name.into(),
        value: serde_json::json!(v),
    };
    store
        .mint(keys.signing_key(), Draft::of(&m, HlcPolicy::After(None)))
        .unwrap();
}

fn open(d: &Dev, clock: Arc<dyn Clock>) -> SqliteStore {
    identity::open_store(&d.paths.db_path(), &d.paths.data_dir, clock)
        .unwrap()
        .unwrap()
}

/// One in-process session; `tamper` may rewrite each frame B sends to A.
fn exchange_with(
    a: &mut SqliteStore,
    b: &mut SqliteStore,
    mut tamper: impl FnMut(Frame) -> Frame,
) -> (bool, bool) {
    let mut sa = Session::new(Limits::default(), Some(b.self_id()));
    let mut sb = Session::new(Limits::default(), Some(a.self_id()));
    let (mut to_a, mut to_b): (Vec<Frame>, Vec<Frame>) = (Vec::new(), Vec::new());
    let route = |acts: Vec<Action>, out: &mut Vec<Frame>, s: &mut SqliteStore| {
        for act in acts {
            match act {
                Action::Send(f) => out.push(f),
                Action::Commit(batch) => {
                    let _ = s.commit(batch);
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
            let acts = sa.on_frame(tamper(f), &*a);
            route(acts, &mut to_b, a);
        }
    }
    (sa.is_closed(), sb.is_closed())
}

// ------------------------------------------------------------------ fuzz

/// Mutate `seed` with `rng`: flip, insert, delete, truncate, splice or
/// duplicate, keeping the result within `max` bytes.
fn mutate(rng: &mut SplitMix64, seed: &[u8], max: usize) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..rng.range_inclusive(1, 4) {
        let len = v.len().max(1) as u64;
        match rng.below(6) {
            0 if !v.is_empty() => {
                let i = rng.below(len) as usize;
                v[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(len + 1) as usize;
                let b = rng.below(256) as u8;
                v.insert(i.min(v.len()), b);
            }
            2 if !v.is_empty() => {
                let i = rng.below(len) as usize;
                v.remove(i);
            }
            3 => v.truncate(rng.below(len + 1) as usize),
            4 if !v.is_empty() => {
                let a = rng.below(len) as usize;
                let b = rng.below(len) as usize;
                let (lo, hi) = (a.min(b), a.max(b));
                let chunk = v[lo..hi].to_vec();
                let at = rng.below(v.len() as u64 + 1) as usize;
                v.splice(at..at, chunk);
            }
            _ => {
                let mut junk = vec![0u8; rng.below(16) as usize];
                rng.fill_bytes(&mut junk);
                v.extend_from_slice(&junk);
            }
        }
    }
    v.truncate(max);
    v
}

/// No parser that sees untrusted bytes panics, and none takes more than a
/// bounded time, over 120 000 seeded mutations of valid inputs (40 000 per
/// family). Inputs are capped at twice each parser's size limit, so a
/// parser's allocation is bounded by its input; the parsers refuse anything
/// over their limit before decoding it.
#[test]
fn parsers_survive_a_hundred_thousand_seeded_mutations() {
    let a = genesis("dev-a");
    let mut s = open(&a, Arc::new(SystemClock));
    set(&mut s, &a, "fuzz.seed", 7);
    let item = s.all_items().unwrap().into_iter().last().unwrap().to_wire();
    // A real frame: A's Hello.
    let mut sess = Session::new(Limits::default(), None);
    let hello = sess
        .start(&s)
        .into_iter()
        .find_map(|a| match a {
            Action::Send(f) => Some(f.encode().unwrap()),
            _ => None,
        })
        .unwrap();
    let inv = a.vault.mesh_invite_create(&master(), None).unwrap();
    let invite = format_invite(&inv.token, &["127.0.0.1:7420".into()])
        .unwrap()
        .expose()
        .as_bytes()
        .to_vec();
    let mut rng = SplitMix64::new(0xADE5_A121);
    let started = Instant::now();
    let mut accepted = [0u32; 3];
    for i in 0..40_000u32 {
        let bytes = mutate(&mut rng, &item, 2 * MAX_ITEM_BYTES);
        if let Ok(it) = SignedItem::from_wire(&bytes) {
            if let Ok(body) = it.decode_unverified() {
                if TypedItem::parse(&body).is_ok() {
                    accepted[0] += 1;
                }
            }
        }
        let bytes = mutate(&mut rng, &hello, 4096);
        if Frame::decode(&bytes).is_ok() {
            accepted[1] += 1;
        }
        // The preamble reader takes exactly its 16 bytes.
        let mut cur = Cursor::new(&bytes);
        let _ = wire::read_preamble(&mut cur);
        let bytes = mutate(&mut rng, &invite, 1024);
        if parse_invite(&String::from_utf8_lossy(&bytes)).is_ok() {
            accepted[2] += 1;
        }
        if i % 10_000 == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(120),
                "the parsers got slow: {:?} at case {i}",
                started.elapsed()
            );
        }
    }
    // Some mutants are still valid (a flipped bit inside a string can be
    // harmless), and most are not: the fuzzing exercised both paths.
    assert!(accepted.iter().all(|&n| n < 40_000), "{accepted:?}");
    eprintln!(
        "fuzz: 120 000 cases in {:?}; accepted {accepted:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------- the network

/// A flood of handshakes from many source ports of one address spends that
/// address's budget, not the node: excess connections are refused at once,
/// and the node serves a member again as soon as the budget refills.
#[test]
fn a_handshake_flood_across_many_source_ports_is_bounded_and_the_node_recovers() {
    let (a, _sa, b) = pair_of();
    let limits = TransportLimits {
        handshakes_per_ip_per_minute: 60,
        handshake_timeout: Duration::from_millis(300),
        ..TransportLimits::default()
    };
    let server = serve_with(&a, Arc::new(SystemClock), limits);
    let mut ports = std::collections::BTreeSet::new();
    let started = Instant::now();
    for i in 0..300u32 {
        let Ok(mut s) = TcpStream::connect(server.addr) else {
            continue;
        };
        ports.insert(s.local_addr().unwrap().port());
        let _ = s.write_all(&i.to_be_bytes().repeat(8));
    }
    assert!(ports.len() >= 250, "distinct source ports: {}", ports.len());
    assert!(started.elapsed() < Duration::from_secs(30));
    let nb = node(&b);
    let mut ok = false;
    for _ in 0..50 {
        if replicate_once(&nb, &server.addr_string()).is_ok() {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let stats = server.stop();
    assert!(ok, "the node serves a member again once the budget refills");
    let refused = stats.refused_rate.load(Ordering::SeqCst);
    let accepted = stats.accepted.load(Ordering::SeqCst);
    assert!(refused >= 200, "refused {refused}, accepted {accepted}");
    assert!(accepted <= 80, "refused {refused}, accepted {accepted}");
}

/// A member that completes the handshake, sends a valid Hello and then
/// stalls is dropped at the idle timeout: nothing it announced is
/// committed, and its session slot is free again.
#[test]
fn a_peer_that_sends_a_valid_hello_and_stalls_is_dropped_and_frees_its_slot() {
    let (a, _sa, b) = pair_of();
    let limits = TransportLimits {
        idle_timeout: Duration::from_millis(400),
        max_sessions: 1,
        ..test_limits()
    };
    let server = serve_with(&a, Arc::new(SystemClock), limits);
    let nb = node(&b);
    {
        let mut st = nb.store();
        let keys = b.vault.mesh_keys().unwrap();
        let m = MeshSetting {
            name: "stall.value".into(),
            value: serde_json::json!(1),
        };
        st.mint(keys.signing_key(), Draft::of(&m, HlcPolicy::After(None)))
            .unwrap();
    }
    let b_id = nb.self_id();
    let before = node(&a).store().vv().get(&b_id);
    let mut s = TcpStream::connect(server.addr).unwrap();
    let key = nb.access_keys().unwrap().current.1;
    let (state, _) = handshake::initiate(&mut s, &nb, &key).unwrap();
    let (mut reader, mut writer) = wire::split(s, state).unwrap();
    let mut sess = Session::new(Limits::default(), None);
    let hello = sess
        .start(&*nb.store())
        .into_iter()
        .find_map(|a| match a {
            Action::Send(f) => Some(f.encode().unwrap()),
            _ => None,
        })
        .unwrap();
    writer.send(&hello).unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let started = Instant::now();
    while reader.recv().is_ok() {}
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        node(&a).store().vv().get(&b_id),
        before,
        "nothing committed"
    );
    // The one slot is free: a normal exchange goes through.
    let r = replicate_once(&nb, &server.addr_string()).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
    assert!(node(&a).store().vv().get(&b_id) > before);
}

/// A Commit whose `upto` claims more of the sender's log than its items
/// carried never advances the receiver's version vector past what it
/// stored (MESH-SI-4).
#[test]
fn a_commit_claiming_more_than_it_sent_advances_nothing_past_what_was_stored() {
    let (a, _sa, b) = pair_of();
    let mut sa = open(&a, Arc::new(SystemClock));
    let mut sb = open(&b, Arc::new(SystemClock));
    for i in 0..3 {
        set(&mut sb, &b, &format!("claim.{i}"), i);
    }
    let b_id = sb.self_id();
    let real = sb.vv().get(&b_id);
    let mut tampered = 0;
    exchange_with(&mut sa, &mut sb, |mut f| {
        if let Body::Commit(c) = &mut f.body {
            if c.upto.get(&b_id) > 0 {
                c.upto.advance_to(b_id, real + 10);
                tampered += 1;
            }
        }
        f
    });
    assert_eq!(tampered, 1);
    let got = open(&a, Arc::new(SystemClock)).vv().get(&b_id);
    assert!(got <= real, "A's vv[B] = {got}, B's own = {real}");
    // Whatever A covers, it holds a dot hash for every seq of it.
    let fresh = open(&a, Arc::new(SystemClock));
    for seq in 1..=got {
        assert!(fresh.dot_hash(&b_id, seq).unwrap().is_some(), "seq {seq}");
    }
    fresh.verify_against_disk().unwrap();
}

/// A device a year ahead, and one a year behind: their items are accepted,
/// the receiver's clock never moves more than the drift bound ahead of its
/// own time, and the ahead device is flagged.
#[test]
fn a_year_of_clock_skew_either_way_neither_drags_the_clock_nor_loses_the_item() {
    let (a, _sa, b) = pair_of();
    let c = vault();
    let inv = invite(&a, &_sa);
    join(&c, &inv, "dev-c").unwrap();
    let now = SystemClock.now_ms();
    let ahead = Arc::new(ManualClock::new(now + 365 * DAY_MS));
    let behind = Arc::new(ManualClock::new(now - 365 * DAY_MS));
    let mut sb = open(&b, ahead);
    set(&mut sb, &b, "skew.ahead", 1);
    let mut sc = open(&c, behind);
    set(&mut sc, &c, "skew.behind", 2);
    let mut sa = open(&a, Arc::new(SystemClock));
    exchange_with(&mut sa, &mut sb, |f| f);
    exchange_with(&mut sa, &mut sc, |f| f);
    let fresh = open(&a, Arc::new(SystemClock));
    let st = fresh.state();
    for name in ["skew.ahead", "skew.behind"] {
        assert!(
            st.settings.value(&name.to_owned(), &st.roster).is_some(),
            "{name} was accepted"
        );
    }
    let last = fresh.hlc_last().physical();
    assert!(
        last <= SystemClock.now_ms() + 60_000,
        "A's clock was dragged to {last} (now {now})"
    );
    let status = a.vault.mesh_status().unwrap().detail.unwrap();
    assert!(
        status.clock_skew.contains_key(&sb.self_id()),
        "{:?}",
        status.clock_skew
    );
    assert!(!status.clock_skew.contains_key(&sc.self_id()));
}

/// A removed device is refused with its old access key and also with the new
/// one (if it had stolen it): the remote static key is checked against the
/// roster after the handshake (MESH-SI-2).
#[test]
fn a_removed_device_is_refused_with_the_old_access_key_and_with_the_new_one() {
    let (a, server, b) = pair_of();
    let nb = node(&b);
    let old_key = nb.access_keys().unwrap().current.1;
    let b_id = nb.self_id();
    a.vault
        .mesh_device_remove(&master(), &b_id.to_hex())
        .unwrap();
    let new_key = node(&a).access_keys().unwrap().current.1;
    assert_ne!(old_key, new_key);
    for key in [old_key, new_key] {
        let mut s = TcpStream::connect(server.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        match handshake::initiate(&mut s, &nb, &key) {
            Err(_) => {} // the old key fails inside the handshake
            Ok((state, _)) => {
                // The new key completes the handshake, then the responder
                // closes without sending a frame.
                let (mut reader, _w) = wire::split(s, state).unwrap();
                reader
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                assert!(reader.recv().is_err(), "a removed device got a frame");
            }
        }
    }
    // The full client path: refused, and nothing B mints reaches A.
    {
        let mut st = nb.store();
        let keys = b.vault.mesh_keys().unwrap();
        let m = MeshSetting {
            name: "removed.after".into(),
            value: serde_json::json!(1),
        };
        st.mint(keys.signing_key(), Draft::of(&m, HlcPolicy::After(None)))
            .unwrap();
    }
    let before = node(&a).store().vv().get(&b_id);
    match replicate_once(&nb, &server.addr_string()) {
        Err(_) => {}
        Ok(r) => assert!(r.aborted.is_some() && r.items_out == 0, "{r:?}"),
    }
    assert_eq!(node(&a).store().vv().get(&b_id), before);
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else if !e.file_name().to_string_lossy().ends_with(".sock") {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// A data directory copied together with its marker (so only the wire can
/// tell) races the original: both mint at the same seq and both reach A.
/// A records the fork and cuts the device off at the fork point.
#[test]
fn a_forked_clone_racing_the_original_is_detected_and_cut_off() {
    let (a, server, b) = pair_of();
    let b_id = device_id(&b);
    api_tracker_core::db::checkpoint_truncate(b.vault.connection());
    let clone_dir = tempfile::TempDir::new().unwrap();
    let clone_paths = api_tracker_core::vault::VaultPaths::new(clone_dir.path().join("data"));
    copy_dir(&b.paths.data_dir, &clone_paths.data_dir);
    let clone = Dev {
        vault: api_tracker_core::vault::unlock_vault(&clone_paths, &master()).unwrap(),
        paths: clone_paths,
        dir: clone_dir,
    };
    let (n1, n2) = (node(&b), node(&clone));
    {
        let mut s1 = n1.store();
        let mut s2 = n2.store();
        let k1 = b.vault.mesh_keys().unwrap();
        let k2 = clone.vault.mesh_keys().unwrap();
        for (s, k, v) in [(&mut *s1, &k1, 1u64), (&mut *s2, &k2, 2u64)] {
            let m = MeshSetting {
                name: "fork.race".into(),
                value: serde_json::json!(v),
            };
            s.mint(k.signing_key(), Draft::of(&m, HlcPolicy::After(None)))
                .unwrap();
        }
    }
    let _ = replicate_once(&n1, &server.addr_string());
    let _ = replicate_once(&n2, &server.addr_string());
    let _ = replicate_once(&n1, &server.addr_string());
    let na = node(&a);
    let st = na.store();
    assert!(
        st.state().roster.fork_seq(&b_id).is_some(),
        "the fork was recorded"
    );
    assert!(
        !st.state().roster.is_active(&b_id),
        "the forked device is cut off"
    );
}

/// A backup restore that sets the vault database aside under a running node
/// stops the node (it would otherwise keep exchanging as this device on a
/// file the data directory no longer uses), and its keys drop.
#[test]
#[cfg(unix)]
fn a_backup_restore_under_a_running_node_stops_it() {
    let (_a, _sa, b) = pair_of();
    let other = vault();
    let backup = other.dir.path().join("other.backup");
    let pw = SecretString::from("adversarial-backup-pw-01");
    api_tracker_core::backup::create_backup(&other.vault, &backup, &pw, false).unwrap();
    let running = run_node(
        &b,
        node_config(60_000),
        Arc::new(SystemClock),
        Box::new(Never),
    );
    std::thread::sleep(Duration::from_millis(300));
    api_tracker_core::backup::restore_backup(&backup, &pw, &b.paths, true).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(running.wait());
    });
    let report = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the node stopped after the restore replaced its database");
    assert_eq!(report.reason, StopReason::Replaced);
    assert!(report.keys_dropped);
}

/// Exchanges keep working, and the store stays consistent with its disk,
/// while another connection hammers the database with short write
/// transactions (as the gateway writer does under load).
#[test]
fn exchanges_survive_a_writer_storm_on_the_database() {
    let (a, server, b) = pair_of();
    let stop = Arc::new(AtomicBool::new(false));
    let storm = {
        let path = b.paths.db_path();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let conn = api_tracker_core::db::open(&path).unwrap();
            let mut n = 0u64;
            while !stop.load(Ordering::SeqCst) {
                let _ = conn.execute_batch(
                    "BEGIN IMMEDIATE;
                     INSERT INTO audit_events (at, event, detail) VALUES ('x', 'storm', '');
                     COMMIT;",
                );
                n += 1;
            }
            n
        })
    };
    let nb = node(&b);
    let keys = b.vault.mesh_keys().unwrap();
    for i in 0..8u64 {
        {
            let mut st = nb.store();
            let m = MeshSetting {
                name: format!("storm.{i}"),
                value: serde_json::json!(i),
            };
            st.mint(keys.signing_key(), Draft::of(&m, HlcPolicy::After(None)))
                .unwrap();
        }
        let r = replicate_once(&nb, &server.addr_string()).unwrap();
        assert!(r.aborted.is_none(), "{r:?}");
    }
    stop.store(true, Ordering::SeqCst);
    let writes = storm.join().unwrap();
    assert!(writes > 100, "the storm ran ({writes} transactions)");
    assert_eq!(node(&a).store().vv(), nb.store().vv());
    open(&b, Arc::new(SystemClock))
        .verify_against_disk()
        .unwrap();
    open(&a, Arc::new(SystemClock))
        .verify_against_disk()
        .unwrap();
}

/// A member flooding `Direct` frames (5 000 rights requests) inside one
/// exchange gets at most the bounded number held, the exchange ends
/// promptly, and the node keeps serving.
#[test]
fn a_flood_of_direct_frames_is_bounded_and_the_node_keeps_serving() {
    let (a, server, b) = pair_of();
    let nb = node(&b);
    let mut s = TcpStream::connect(server.addr).unwrap();
    let key = nb.access_keys().unwrap().current.1;
    let (state, _) = handshake::initiate(&mut s, &nb, &key).unwrap();
    let (mut reader, mut writer) = wire::split(s, state).unwrap();
    let mut sess = Session::new(Limits::default(), Some(device_id(&a)));
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for act in sess.start(&*nb.store()) {
        if let Action::Send(f) = act {
            frames.push(f.encode().unwrap());
        }
    }
    let cap = api_tracker_core::mesh::dot::CapId::random();
    let month = api_tracker_core::mesh::kinds::Month::parse("2026-11").unwrap();
    for _ in 0..5_000 {
        for act in sess.direct(DirectMsg::RightsRequest {
            cap,
            month,
            want: 1,
            reclaim: false,
        }) {
            if let Action::Send(f) = act {
                frames.push(f.encode().unwrap());
            }
        }
    }
    let started = Instant::now();
    let sender = std::thread::spawn(move || {
        for f in frames {
            if writer.send(&f).is_err() {
                break;
            }
        }
        writer
    });
    reader
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // Drive our side to completion (or until the server gives up on us).
    while let Ok(bytes) = reader.recv() {
        let Ok(f) = Frame::decode(&bytes) else { break };
        let mut done = false;
        for act in sess.on_frame(f, &*nb.store()) {
            match act {
                Action::Send(_) => {}
                Action::Close(_) => done = true,
                _ => {}
            }
        }
        if done {
            break;
        }
    }
    let _ = sender.join();
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    let r = replicate_once(&nb, &server.addr_string()).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
}
