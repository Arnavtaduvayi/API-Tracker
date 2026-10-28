//! Tethra Mesh membership rules in core (Increment 04, PROTOCOL.md §9):
//! access-key rotation bounds and tie-breaks, removal preconditions, invite
//! liveness. The network paths are in `crates/mesh/tests`.

mod common;

use api_tracker_core::error::CoreError;
use api_tracker_core::mesh::invite::AccessKey;
use api_tracker_core::mesh::membership::{self, max_access_epoch};
use api_tracker_core::mesh::MeshError;
use common::{master_pw, new_vault};
use zeroize::Zeroizing;

fn key(b: u8) -> AccessKey {
    AccessKey(Zeroizing::new([b; 32]))
}

fn epoch(v: &api_tracker_core::vault::UnlockedVault) -> u32 {
    v.connection()
        .query_row("SELECT access_key_epoch FROM mesh_self", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn an_access_key_epoch_must_be_justified_by_removals() {
    let (_d, _p, v) = new_vault();
    v.mesh_init("dev-a").unwrap();
    let mv = v.mesh_vault();
    let conn = v.connection();
    let store = v.mesh_open_store().unwrap();
    assert_eq!(max_access_epoch(&store), 1, "no removals known");
    // A member cannot jump the epoch: not to 2 without a removal, and never
    // to u32::MAX (which would block every later rotation).
    for e in [2, 1000, u32::MAX] {
        assert!(!mv.accept_access_key(conn, e, &key(9), 1).unwrap());
    }
    assert_eq!(epoch(&v), 1);
    // With a removal known, epoch 2 is accepted.
    assert!(mv.accept_access_key(conn, 2, &key(9), 2).unwrap());
    assert_eq!(epoch(&v), 2);
    assert!(
        !mv.accept_access_key(conn, 1, &key(8), 2).unwrap(),
        "never backwards"
    );
}

#[test]
fn two_keys_for_one_epoch_converge_on_the_larger_hash() {
    let (_d1, _p1, a) = new_vault();
    a.mesh_init("dev-a").unwrap();
    let (_d2, _p2, b) = new_vault();
    b.mesh_init("dev-b").unwrap();
    let (ka, kb) = (key(1), key(2));
    // Each "rotated" to epoch 2 on its own (concurrent removals).
    assert!(a
        .mesh_vault()
        .accept_access_key(a.connection(), 2, &ka, 3)
        .unwrap());
    assert!(b
        .mesh_vault()
        .accept_access_key(b.connection(), 2, &kb, 3)
        .unwrap());
    // They exchange keys: exactly one side changes, and both end equal.
    let a_moved = a
        .mesh_vault()
        .accept_access_key(a.connection(), 2, &kb, 3)
        .unwrap();
    let b_moved = b
        .mesh_vault()
        .accept_access_key(b.connection(), 2, &ka, 3)
        .unwrap();
    assert!(a_moved ^ b_moved, "exactly one adopts the other's key");
    let now = u64::MAX / 2;
    let ca = a
        .mesh_vault()
        .access_keys(a.connection(), now)
        .unwrap()
        .current;
    let cb = b
        .mesh_vault()
        .access_keys(b.connection(), now)
        .unwrap()
        .current;
    assert_eq!(ca.0, 2);
    assert_eq!(ca.1, cb.1, "both hold the same epoch-2 key");
    let winner = if blake3::hash(ka.expose()).as_bytes() > blake3::hash(kb.expose()).as_bytes() {
        ka
    } else {
        kb
    };
    assert_eq!(ca.1, winner);
}

#[test]
fn the_previous_key_is_the_newest_below_the_current_even_after_a_skip() {
    let (_d, _p, v) = new_vault();
    v.mesh_init("dev-a").unwrap();
    let first = v
        .mesh_vault()
        .access_keys(v.connection(), 0)
        .unwrap()
        .current
        .1;
    assert!(v
        .mesh_vault()
        .accept_access_key(v.connection(), 3, &key(3), 3)
        .unwrap());
    let now =
        api_tracker_core::mesh::clock::Clock::now_ms(&api_tracker_core::mesh::clock::SystemClock);
    let keys = v.mesh_vault().access_keys(v.connection(), now).unwrap();
    assert_eq!(keys.current.0, 3);
    assert_eq!(keys.previous, Some((1, first)), "epoch 2 was never held");
    // After the 30-day grace there is no previous key.
    let later = now + membership::PREVIOUS_EPOCH_GRACE_MS + 1;
    let keys = v.mesh_vault().access_keys(v.connection(), later).unwrap();
    assert!(keys.previous.is_none());
}

#[test]
fn removal_needs_an_active_device_and_a_device_not_yet_removed() {
    let (_d, _p, v) = new_vault();
    v.mesh_init("dev-a").unwrap();
    let me = v.mesh_status().unwrap().detail.unwrap().device_id;
    // Removing oneself is leaving.
    assert!(matches!(
        v.mesh_device_remove(&master_pw(), &me.to_hex()),
        Err(CoreError::InvalidInput(_))
    ));
    // An unknown device.
    assert!(matches!(
        v.mesh_device_remove(&master_pw(), "0123456789abcdef"),
        Err(CoreError::Mesh(MeshError::NotAMember))
    ));
    assert_eq!(epoch(&v), 1, "nothing rotated");
}

#[test]
fn a_device_that_left_its_roster_cannot_invite_and_invites_report_liveness() {
    let (_d, _p, v) = new_vault();
    v.mesh_init("dev-a").unwrap();
    let inv = v.mesh_invite_create(&master_pw(), None).unwrap();
    let hash = inv.token.hash();
    assert!(membership::invite_is_live(v.connection(), &hash).unwrap());
    for _ in 0..5 {
        membership::record_failed_attempt(v.connection(), &hash).unwrap();
    }
    assert!(
        !membership::invite_is_live(v.connection(), &hash).unwrap(),
        "five failed attempts end it"
    );
    assert!(!membership::invite_is_live(v.connection(), &[0; 32]).unwrap());
    // This device removes itself from its own roster (as `leave` does before
    // the wipe): it no longer admits anyone.
    let keys = v.mesh_keys().unwrap();
    let mut store = v.mesh_open_store().unwrap();
    let me = api_tracker_core::mesh::store::MeshStore::self_id(&store);
    let remove = api_tracker_core::mesh::kinds::RosterRemove {
        device: me,
        cutoff_seq: 2,
    };
    api_tracker_core::mesh::store::MeshStore::mint(
        &mut store,
        keys.signing_key(),
        api_tracker_core::mesh::store::Draft::of(
            &remove,
            api_tracker_core::mesh::store::HlcPolicy::Now,
        ),
    )
    .unwrap();
    assert!(matches!(
        v.mesh_invite_create(&master_pw(), None),
        Err(CoreError::Mesh(MeshError::NotActive))
    ));
}
