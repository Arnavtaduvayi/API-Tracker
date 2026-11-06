//! Pairing over real sockets on 127.0.0.1 (Increment 04, DESIGN §D10).

mod common;

use api_tracker_core::mesh::clock::SystemClock;
use api_tracker_core::mesh::invite::{format_invite, parse_invite};
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::MeshError;
use api_tracker_core::CoreError;
use api_tracker_mesh::wire::{self, Preamble, MAX_HANDSHAKE_MSG};
use api_tracker_mesh::{noise, NetError};
use common::*;
use std::net::TcpStream;

fn refused(e: &NetError) -> bool {
    matches!(
        e,
        NetError::Core(CoreError::Mesh(MeshError::InviteRefused(_)))
    ) || matches!(
        e,
        NetError::Refused(_) | NetError::Io(_) | NetError::Handshake(_)
    )
}

#[test]
fn a_device_pairs_and_both_see_two_members() {
    let a = genesis("dev-a");
    let server = start(&a);
    let b = vault();
    let inv = invite(&a, &server);
    let r = join(&b, &inv, "dev-b").unwrap();
    assert!(r.exchange.aborted.is_none(), "{:?}", r.exchange);
    assert!(
        r.inviter_verified,
        "the inviter's key matches its roster entry"
    );
    assert_eq!(
        r.info.genesis_device,
        a.vault.mesh_status().unwrap().detail.unwrap().device_id
    );
    let on_b = b.vault.mesh_devices().unwrap();
    let on_a = a.vault.mesh_devices().unwrap();
    assert_eq!(on_b.len(), 2);
    assert_eq!(on_a.len(), 2);
    assert!(on_a.iter().chain(on_b.iter()).all(|d| d.active));
    // The exchange that followed pairing is logged on both sides.
    assert!(on_b.iter().any(|d| !d.is_self && d.last_exchange.is_some()));
    assert!(server
        .node
        .store()
        .state()
        .roster
        .is_active(&r.info.device_id));
}

#[test]
fn a_token_is_single_use_even_for_two_concurrent_joiners() {
    let a = genesis("dev-a");
    let server = start(&a);
    let inv = invite(&a, &server);
    let (b, c) = (vault(), vault());
    let inv_ref = &inv;
    let results: Vec<bool> = std::thread::scope(|s| {
        let hb = s.spawn(move || join(&b, inv_ref, "dev-b").is_ok());
        let hc = s.spawn(move || join(&c, inv_ref, "dev-c").is_ok());
        vec![hb.join().unwrap(), hc.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|ok| **ok).count(), 1, "{results:?}");
    // And a third try after that is refused too.
    let d = vault();
    let e = join(&d, &inv, "dev-d").unwrap_err();
    assert!(refused(&e), "{e}");
    assert!(
        d.vault.mesh_status().unwrap().detail.is_none(),
        "nothing stored"
    );
}

#[test]
fn an_expired_invite_is_refused() {
    let a = genesis("dev-a");
    let server = start(&a);
    let inv = invite(&a, &server);
    a.vault
        .connection()
        .execute(
            "UPDATE mesh_invites SET expires_at = '2000-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
    let b = vault();
    let e = join(&b, &inv, "dev-b").unwrap_err();
    assert!(refused(&e), "{e}");
    assert!(b.vault.mesh_status().unwrap().detail.is_none());
}

/// Dial with the right hint but a wrong pairing psk.
fn wrong_psk_attempt(addr: &str, hint: [u8; 8]) {
    let mut s = TcpStream::connect(addr).unwrap();
    wire::write_preamble(&mut s, Preamble::Pair { hint }).unwrap();
    let mut secret = [3u8; 32];
    secret[0] &= 248;
    let mut hs = noise::pairing(&[0xEE; 32], &secret, true).unwrap();
    let mut buf = [0u8; MAX_HANDSHAKE_MSG];
    let mut out = [0u8; MAX_HANDSHAKE_MSG];
    let n = hs.write_message(&[], &mut buf).unwrap();
    wire::write_msg(&mut s, &buf[..n]).unwrap();
    let m2 = wire::read_msg(&mut s, MAX_HANDSHAKE_MSG).unwrap();
    hs.read_message(&m2, &mut out).unwrap();
    let n = hs.write_message(&[], &mut buf).unwrap();
    wire::write_msg(&mut s, &buf[..n]).unwrap();
    // The inviter closes without a frame.
    let mut rest = Vec::new();
    let _ = std::io::Read::read_to_end(&mut s, &mut rest);
}

#[test]
fn five_wrong_attempts_lock_the_invite_out() {
    let a = genesis("dev-a");
    let server = start(&a);
    let inv = invite(&a, &server);
    let (token, _) = parse_invite(inv.expose()).unwrap();
    for i in 1..=5 {
        wrong_psk_attempt(&server.addr_string(), token.hint());
        let attempts: i64 = a
            .vault
            .connection()
            .query_row("SELECT attempts FROM mesh_invites", [], |r| r.get(0))
            .unwrap();
        assert_eq!(attempts, i);
    }
    let b = vault();
    let e = join(&b, &inv, "dev-b").unwrap_err();
    assert!(refused(&e), "{e}");
    assert!(b.vault.mesh_status().unwrap().detail.is_none());
}

#[test]
fn a_device_already_in_a_mesh_cannot_join_another() {
    let a = genesis("dev-a");
    let server = start(&a);
    let inv = invite(&a, &server);
    let b = genesis("dev-b");
    let e = join(&b, &inv, "dev-b").unwrap_err();
    assert!(
        matches!(e, NetError::Core(CoreError::Mesh(MeshError::AlreadyInMesh))),
        "{e}"
    );
    // The invite was not touched.
    let used: Option<String> = a
        .vault
        .connection()
        .query_row("SELECT used_at FROM mesh_invites", [], |r| r.get(0))
        .unwrap();
    assert!(used.is_none());
}

#[test]
fn a_typo_fails_before_any_connection_and_a_wrong_mesh_cannot_talk() {
    let a = genesis("dev-a");
    let server = start(&a);
    let inv = invite(&a, &server);
    let s = inv.expose();
    let i = "tethra-mesh-invite:v1:".len() + 3;
    let mut typo = s.as_bytes().to_vec();
    typo[i] = if typo[i] == b'a' { b'b' } else { b'a' };
    let b = vault();
    let e = pair_join(&b, std::str::from_utf8(&typo).unwrap());
    assert!(
        matches!(
            e,
            Err(NetError::Core(CoreError::Mesh(MeshError::InvalidInvite(_))))
        ),
        "{e:?}"
    );
    assert_eq!(
        server.node.store().vv().iter().count(),
        1,
        "nothing reached the inviter"
    );
    // A member of another mesh cannot open a session here.
    let other = genesis("other");
    let n = node(&other);
    let e = api_tracker_mesh::replicate::replicate_once(&n, &server.addr_string()).unwrap_err();
    assert!(matches!(e, NetError::Handshake(_) | NetError::Io(_)), "{e}");
}

fn pair_join(dev: &Dev, invite: &str) -> Result<api_tracker_mesh::pair::JoinReport, NetError> {
    api_tracker_mesh::pair::join(
        &dev.vault,
        invite,
        "dev-x",
        std::sync::Arc::new(api_tracker_core::mesh::clock::SystemClock),
        test_limits(),
    )
}

#[test]
fn the_token_appears_in_no_error_log_or_audit_row() {
    let a = genesis("dev-a");
    let server = start(&a);
    let inv = invite(&a, &server);
    let (token, addrs) = parse_invite(inv.expose()).unwrap();
    let code = &inv.expose()["tethra-mesh-invite:v1:".len()..][..32];
    let mut seen = String::new();
    // Every failure path's message.
    let b = genesis("dev-b");
    seen.push_str(&format!("{}", join(&b, &inv, "x").unwrap_err()));
    let c = vault();
    let mut typo = inv.expose().to_owned();
    typo.push('x');
    seen.push_str(&format!("{:?}", pair_join(&c, &typo).err()));
    seen.push_str(&format!("{token:?}{inv:?}"));
    wrong_psk_attempt(&server.addr_string(), token.hint());
    let r = join(&c, &inv, "dev-c").unwrap();
    seen.push_str(&format!("{r:?}"));
    seen.push_str(&serde_json::to_string(&r).unwrap());
    // The databases' text: audit trail, exchange log, invite rows.
    for d in [&a, &c] {
        let conn = d.vault.connection();
        for (table, col) in [
            ("audit_events", "detail"),
            ("mesh_exchange_log", "COALESCE(error, '')"),
        ] {
            let mut st = conn.prepare(&format!("SELECT {col} FROM {table}")).unwrap();
            let rows: Vec<String> = st
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            seen.push_str(&rows.join("\n"));
        }
    }
    assert!(!seen.contains(code), "the invite code leaked");
    let hash_hex: String = token.hash().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!seen.contains(&hash_hex), "the token hash leaked");
    // Formatting again from the parsed token gives the same secret string;
    // the token itself is never in the clear anywhere else.
    assert_eq!(
        format_invite(&token, &addrs).unwrap().expose(),
        inv.expose()
    );
}

#[test]
fn an_invite_whose_first_address_is_dead_still_pairs_through_the_next() {
    let a = genesis("dev-a");
    let server = start(&a);
    let inv = a.vault.mesh_invite_create(&master(), None).unwrap();
    // Something on the first address answers, but it is not the inviter.
    let impostor = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let impostor_addr = impostor.local_addr().unwrap().to_string();
    let t = std::thread::spawn(move || {
        if let Ok((s, _)) = impostor.accept() {
            drop(s);
        }
    });
    let text = format_invite(&inv.token, &[impostor_addr, server.addr_string()]).unwrap();
    let b = vault();
    let r = join(&b, &text, "dev-b").unwrap();
    assert!(r.exchange.aborted.is_none(), "{:?}", r.exchange);
    t.join().unwrap();
}

fn attempts(a: &Dev) -> i64 {
    a.vault
        .connection()
        .query_row("SELECT attempts FROM mesh_invites", [], |r| r.get(0))
        .unwrap()
}

/// Dial with the right hint, send message 1, read message 2, then `finish`
/// (drop the connection or stall), and wait for the inviter to close.
fn abandoned_attempt(addr: &str, hint: [u8; 8], stall: bool) {
    let mut s = TcpStream::connect(addr).unwrap();
    wire::write_preamble(&mut s, Preamble::Pair { hint }).unwrap();
    let mut secret = [4u8; 32];
    secret[0] &= 248;
    let mut hs = noise::pairing(&[0xEE; 32], &secret, true).unwrap();
    let mut buf = [0u8; MAX_HANDSHAKE_MSG];
    let mut out = [0u8; MAX_HANDSHAKE_MSG];
    let n = hs.write_message(&[], &mut buf).unwrap();
    wire::write_msg(&mut s, &buf[..n]).unwrap();
    let m2 = wire::read_msg(&mut s, MAX_HANDSHAKE_MSG).unwrap();
    hs.read_message(&m2, &mut out).unwrap();
    if !stall {
        // The connection drops before message 3.
        s.shutdown(std::net::Shutdown::Write).unwrap();
    }
    // Wait until the inviter gives up on us (its handshake deadline when
    // stalled) and closes.
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut rest = Vec::new();
    let _ = std::io::Read::read_to_end(&mut s, &mut rest);
}

#[test]
fn a_dropped_connection_does_not_count_as_a_wrong_attempt() {
    // Audit MP-11: only an authenticated failure (message 3 does not
    // decrypt under the invite's psk) burns one of the five attempts; a
    // connection that drops or stalls before message 3 does not.
    let a = genesis("dev-a");
    let limits = api_tracker_mesh::TransportLimits {
        handshake_timeout: std::time::Duration::from_millis(400),
        ..test_limits()
    };
    let server = serve_with(&a, std::sync::Arc::new(SystemClock), limits);
    let inv = invite(&a, &server);
    let (token, _) = parse_invite(inv.expose()).unwrap();
    for i in 0..6 {
        abandoned_attempt(&server.addr_string(), token.hint(), false);
        assert_eq!(attempts(&a), 0, "dropped connection {i} burned an attempt");
    }
    abandoned_attempt(&server.addr_string(), token.hint(), true);
    assert_eq!(attempts(&a), 0, "a stalled handshake burned an attempt");
    // A wrong psk still counts...
    wrong_psk_attempt(&server.addr_string(), token.hint());
    assert_eq!(attempts(&a), 1);
    // ...and the invite still pairs.
    let b = vault();
    let r = join(&b, &inv, "dev-b").unwrap();
    assert!(r.exchange.aborted.is_none(), "{:?}", r.exchange);
}

#[test]
fn join_fails_when_the_inviter_key_does_not_match_its_roster_entry() {
    // Audit MP-12: an "inviter" that answers the pairing handshake with a
    // static key other than the one its roster entry carries. Here it holds
    // the real inviter's store and signing key (so the PairAccept and the
    // exchange are genuine) but not its Noise key: the joiner must fail and
    // keep no identity.
    use api_tracker_core::mesh::clock::Clock;
    use api_tracker_core::mesh::membership;
    use api_tracker_mesh::session::{exchange, Direction};
    let a = genesis("dev-a");
    let inv = a.vault.mesh_invite_create(&master(), None).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let text = format_invite(&inv.token, &[addr]).unwrap();
    let (psk, token_hash) = (inv.token.pairing_psk(), inv.token.hash());
    let node_a = node(&a);
    let access = a
        .vault
        .mesh_vault()
        .access_keys(a.vault.connection(), SystemClock.now_ms())
        .unwrap()
        .current;
    let b = vault();
    std::thread::scope(|scope| {
        let fake = scope.spawn(|| {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            assert!(matches!(
                wire::read_preamble(&mut s).unwrap(),
                Preamble::Pair { .. }
            ));
            // Not dev-a's Noise key.
            let mut secret = [0x42u8; 32];
            secret[0] &= 248;
            let mut hs = noise::pairing(&psk, &secret, false).unwrap();
            let mut buf = [0u8; MAX_HANDSHAKE_MSG];
            let mut out = [0u8; MAX_HANDSHAKE_MSG];
            let m1 = wire::read_msg(&mut s, MAX_HANDSHAKE_MSG).unwrap();
            hs.read_message(&m1, &mut out).unwrap();
            let n = hs.write_message(&[], &mut buf).unwrap();
            wire::write_msg(&mut s, &buf[..n]).unwrap();
            let m3 = wire::read_msg(&mut s, MAX_HANDSHAKE_MSG).unwrap();
            hs.read_message(&m3, &mut out).unwrap();
            let remote = api_tracker_core::mesh::sign::PublicKeyBytes(
                <[u8; 32]>::try_from(hs.get_remote_static().unwrap()).unwrap(),
            );
            let state = hs.into_stateless_transport_mode().unwrap();
            let (mut r, mut w) = wire::split(s, state).unwrap();
            let req: api_tracker_core::mesh::invite::PairRequest =
                serde_json::from_slice(&r.recv().unwrap()).unwrap();
            let accept = {
                let mut store = node_a.store();
                membership::accept_pairing(
                    &mut store,
                    node_a.keys().signing_key(),
                    &token_hash,
                    &req,
                    &remote,
                    &access,
                )
                .unwrap()
            };
            let reply = serde_json::json!({ "t": "Accepted", "accept": accept });
            w.send(&serde_json::to_vec(&reply).unwrap()).unwrap();
            let joiner = api_tracker_core::mesh::sign::derive_device_id(
                &req.sign_pub,
                &req.noise_pub,
                &req.seal_pub,
            );
            exchange(&node_a, r, w, joiner, Direction::Inbound)
        });
        let r = join(&b, &text, "dev-b");
        let _ = fake.join().unwrap();
        assert!(r.is_err(), "joined an unverified inviter: {:?}", r.ok());
    });
    assert!(
        b.vault.mesh_status().unwrap().detail.is_none(),
        "the joiner kept an identity"
    );
}
