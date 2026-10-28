//! Replication over real sockets on 127.0.0.1 (Increment 04): relays,
//! removal at the transport, access-key rotation, and commit-only VVs.

mod common;

use api_tracker_core::mesh::clock::ManualClock;
use api_tracker_core::mesh::kinds::MeshSetting;
use api_tracker_core::mesh::proto::{Action, Body, Frame, Limits, Session};
use api_tracker_core::mesh::store::{Draft, HlcPolicy, MeshStore};
use api_tracker_core::mesh::DeviceId;
use api_tracker_mesh::replicate::replicate_once;
use api_tracker_mesh::{handshake, wire, MeshNode, NetError};
use common::*;
use std::net::TcpStream;
use std::sync::Arc;

fn set(n: &MeshNode, name: &str, v: u64) {
    let m = MeshSetting {
        name: name.into(),
        value: serde_json::json!(v),
    };
    n.store()
        .mint(
            n.keys().signing_key(),
            Draft::of(&m, HlcPolicy::After(None)),
        )
        .unwrap();
}

fn setting(n: &MeshNode, name: &str) -> Option<serde_json::Value> {
    let st = n.store();
    let s = st.state();
    s.settings.value(&name.to_owned(), &s.roster).cloned()
}

fn epoch(d: &Dev) -> i64 {
    d.vault
        .connection()
        .query_row("SELECT access_key_epoch FROM mesh_self", [], |r| r.get(0))
        .unwrap()
}

fn id(d: &Dev) -> DeviceId {
    d.vault.mesh_status().unwrap().detail.unwrap().device_id
}

#[test]
fn two_devices_replicate_both_ways() {
    let (a, server, b) = pair_of();
    let nb = node(&b);
    set(&nb, "from_b", 1);
    let na = node(&a);
    set(&na, "from_a", 2);
    let r = replicate_once(&nb, &server.addr_string()).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
    assert!(r.items_in >= 1 && r.items_out >= 1, "{r:?}");
    assert_eq!(setting(&server.node, "from_b"), Some(serde_json::json!(1)));
    assert_eq!(setting(&nb, "from_a"), Some(serde_json::json!(2)));
    assert_eq!(nb.store().vv(), server.node.store().vv());
    drop(a);
}

#[test]
fn a_items_reach_c_through_b_and_verify_at_c() {
    let a = genesis("dev-a");
    let sa = start(&a);
    let b = vault();
    join(&b, &invite(&a, &sa), "dev-b").unwrap();
    let sb = start(&b);
    let c = vault();
    join(&c, &invite(&b, &sb), "dev-c").unwrap();
    // A writes; C never talks to A.
    let na = node(&a);
    set(&na, "relayed", 7);
    let nb = node(&b);
    replicate_once(&nb, &sa.addr_string()).unwrap();
    let nc = node(&c);
    let r = replicate_once(&nc, &sb.addr_string()).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
    assert_eq!(setting(&nc, "relayed"), Some(serde_json::json!(7)));
    // C holds A's item byte for byte, and it verifies with A's key from C's
    // own roster.
    let a_id = id(&a);
    let st = nc.store();
    let keys = st
        .state()
        .roster
        .keys(&a_id)
        .unwrap()
        .sign_pub
        .to_verifying_key()
        .unwrap();
    let mesh = st.genesis().mesh_id;
    let held = st.held_items(&a_id, 0, u64::MAX).unwrap();
    assert!(!held.is_empty());
    for item in held {
        let (body, sig) = (item.body_bytes().to_vec(), *item.sig());
        api_tracker_core::mesh::item::SignedItem::verify(&body, &sig, &keys, &mesh).unwrap();
    }
}

#[test]
fn a_removed_device_is_refused_and_its_later_writes_stop_counting() {
    let a = genesis("dev-a");
    let sa = start(&a);
    let b = vault();
    join(&b, &invite(&a, &sa), "dev-b").unwrap();
    let c = vault();
    join(&c, &invite(&a, &sa), "dev-c").unwrap();
    let nb = node(&b);
    replicate_once(&nb, &sa.addr_string()).unwrap(); // B learns of C
    let c_id = id(&c);
    // B removes C: roster.remove plus an access-key rotation.
    let (removed, new_epoch) = b
        .vault
        .mesh_device_remove(&master(), &c_id.to_hex()[..12])
        .unwrap();
    assert_eq!((removed, new_epoch), (c_id, 2));
    // Removing it again is refused, and does not rotate again.
    let again = b.vault.mesh_device_remove(&master(), &c_id.to_hex());
    assert!(
        matches!(
            again,
            Err(api_tracker_core::CoreError::Mesh(
                api_tracker_core::mesh::MeshError::AlreadyRemoved
            ))
        ),
        "{again:?}"
    );
    assert_eq!(epoch(&b), 2);
    let sb = start(&b);
    // B refuses C at the transport.
    let nc = node(&c);
    match replicate_once(&nc, &sb.addr_string()) {
        Ok(r) => assert!(r.aborted.is_some(), "{r:?}"),
        Err(e) => assert!(
            matches!(
                e,
                NetError::Handshake(_) | NetError::Refused(_) | NetError::Io(_)
            ),
            "{e}"
        ),
    }
    // C writes after its cutoff and reaches A, which has not heard yet.
    set(&nc, "c_note", 9);
    let r = replicate_once(&nc, &sa.addr_string()).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
    assert_eq!(setting(&sa.node, "c_note"), Some(serde_json::json!(9)));
    // A hears of the removal from B (and of the new key: rotation reaches A
    // through B)...
    let na = node(&a);
    let r = replicate_once(&na, &sb.addr_string()).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
    assert_eq!(epoch(&a), 2);
    // ...so C's post-cutoff write is excluded on A, and A refuses C too.
    assert_eq!(setting(&sa.node, "c_note"), None);
    assert!(sa.node.store().state().roster.is_removed(&c_id));
    match replicate_once(&nc, &sa.addr_string()) {
        Ok(r) => assert!(r.aborted.is_some(), "{r:?}"),
        Err(e) => assert!(
            matches!(
                e,
                NetError::Handshake(_) | NetError::Refused(_) | NetError::Io(_)
            ),
            "{e}"
        ),
    }
}

#[test]
fn a_device_that_missed_a_rotation_for_over_30_days_is_refused() {
    let a = genesis("dev-a");
    let sa = start(&a);
    let b = vault();
    join(&b, &invite(&a, &sa), "dev-b").unwrap();
    let d = vault();
    join(&d, &invite(&a, &sa), "dev-d").unwrap();
    // A removes B: epoch 2. D still holds epoch 1.
    a.vault
        .mesh_device_remove(&master(), &id(&b).to_hex())
        .unwrap();
    assert_eq!((epoch(&a), epoch(&d)), (2, 1));
    let nd = node(&d);
    // 31 days later, A no longer accepts epoch 1.
    let now =
        api_tracker_core::mesh::clock::Clock::now_ms(&api_tracker_core::mesh::clock::SystemClock);
    let later = serve_with(
        &a,
        Arc::new(ManualClock::new(now + 31 * 24 * 3_600_000)),
        test_limits(),
    );
    let e = replicate_once(&nd, &later.addr_string()).unwrap_err();
    assert!(matches!(e, NetError::Handshake(_) | NetError::Io(_)), "{e}");
    assert_eq!(epoch(&d), 1);
    // Within the 30 days it gets through and receives the new key.
    let r = replicate_once(&nd, &sa.addr_string()).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
    assert_eq!(epoch(&d), 2);
    // And from then on it uses the new key directly.
    let r = replicate_once(&nd, &later.addr_string()).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
}

#[test]
fn a_sender_killed_mid_session_advances_no_vv() {
    let (a, server, b) = pair_of();
    let nb = node(&b);
    for i in 0..40 {
        set(&nb, &format!("k{i}"), i);
    }
    let b_id = id(&b);
    let before = server.node.store().vv().get(&b_id);
    // B authenticates for real, then sends its Items but dies before Commit.
    let mut stream = TcpStream::connect(server.addr).unwrap();
    let key = nb.access_keys().unwrap().current.1;
    let (state, peer) = handshake::initiate(&mut stream, &nb, &key).unwrap();
    let (mut reader, mut writer) = wire::split(stream, state).unwrap();
    let mut session = Session::new(Limits::default(), Some(peer));
    for act in session.start(&*nb.store()) {
        if let Action::Send(f) = act {
            writer.send(&f.encode().unwrap()).unwrap();
        }
    }
    let mut sent_items = false;
    while !sent_items {
        let frame = Frame::decode(&reader.recv().unwrap()).unwrap();
        let acts = session.on_frame(frame, &*nb.store());
        for act in acts {
            if let Action::Send(f) = act {
                match f.body {
                    Body::Items(_) => {
                        writer.send(&f.encode().unwrap()).unwrap();
                        sent_items = true;
                    }
                    Body::Commit(_) => {}
                    _ => writer.send(&f.encode().unwrap()).unwrap(),
                }
            }
        }
    }
    drop(writer);
    drop(reader);
    wait_until(
        || {
            a.vault
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM mesh_exchange_log WHERE peer_device = ?1 AND result = 'aborted'",
                    [b_id.to_hex()],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
                >= 1
        },
        "the server to log the aborted exchange",
    );
    assert_eq!(
        server.node.store().vv().get(&b_id),
        before,
        "no Commit, no VV"
    );
    // A complete exchange afterwards delivers everything.
    let r = replicate_once(&nb, &server.addr_string()).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
    assert_eq!(
        server.node.store().vv().get(&b_id),
        nb.store().vv().get(&b_id)
    );
}

#[test]
fn a_name_that_resolves_to_several_addresses_reaches_the_ipv4_listener() {
    let (_a, server, b) = pair_of();
    let nb = node(&b);
    // `localhost` may resolve to [::1] first; the server listens on 127.0.0.1.
    let r = replicate_once(&nb, &format!("localhost:{}", server.addr.port())).unwrap();
    assert!(r.aborted.is_none(), "{r:?}");
}
