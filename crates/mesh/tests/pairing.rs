//! Pairing over real sockets on 127.0.0.1 (Increment 04, DESIGN §D10).

mod common;

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
