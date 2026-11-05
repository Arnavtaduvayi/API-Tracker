//! Tethra Mesh: regression tests for the protocol findings of the
//! 2026-11-03 audit (`docs/mesh/audit/2026-11-03/FINDINGS_INDEX.md`, `MP-`
//! rows) that need more than one module: real vaults, the sans-IO session
//! and the in-memory store together.
//!
//! Every credential value here is an unmistakably fake test string.

mod common;

use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::kinds::RosterAdd;
use api_tracker_core::mesh::membership::{self, PendingIdentity};
use api_tracker_core::mesh::share::Recipients;
use api_tracker_core::mesh::sign::{derive_device_id, PublicKeyBytes, SigningKeyPair};
use api_tracker_core::mesh::store::{Draft, HlcPolicy, MeshStore};
use api_tracker_core::model::Environment;
use common::{add_key, add_project, master_pw, new_vault, FAKE_KEY_1};

// ------------------------------------------------------------------ MP-5

/// X25519's all-zero point: the shared secret with it is all zeros whatever
/// the secret key, so a box sealed to it is readable by anyone.
const ZERO_POINT: PublicKeyBytes = PublicKeyBytes([0; 32]);

/// The order-8 point `5f9c…1157` with bit 255 set (X25519 ignores the bit).
fn order_eight_high_bit() -> PublicKeyBytes {
    let mut b = [0u8; 32];
    hex::decode_to_slice(
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        &mut b,
    )
    .unwrap();
    PublicKeyBytes(b)
}

#[test]
fn a_small_order_seal_key_is_refused_so_no_share_can_be_sealed_to_it() {
    let (_dir, _paths, mut v) = new_vault();
    let app = add_project(&mut v, "app").id;
    v.mesh_init("dev-a").unwrap();
    v.mesh_project_share(&app).unwrap();
    let (cred, _) = add_key(
        &mut v,
        &app,
        "OPENAI_API_KEY",
        FAKE_KEY_1,
        Environment::Development,
    );
    let keys = v.mesh_keys().unwrap();
    let real = PendingIdentity::generate("real keys").unwrap().request();
    let me = v.mesh_open_store().unwrap().self_id();
    let shares_before: i64 = v
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM mesh_items WHERE kind = 'share.sealed'",
            [],
            |r| r.get(0),
        )
        .unwrap();

    for bad in [ZERO_POINT, order_eight_high_bit()] {
        for (noise_pub, seal_pub) in [(real.noise_pub, bad), (bad, real.seal_pub)] {
            let sign_pub = SigningKeyPair::generate().public_key();
            let device = derive_device_id(&sign_pub, &noise_pub, &seal_pub);
            let add = RosterAdd {
                device,
                name: "small order".into(),
                sign_pub,
                noise_pub,
                seal_pub,
                added_by: me,
            };
            // A member cannot mint the add (an invalid payload, R10)...
            let mut store = v.mesh_open_store().unwrap();
            let seq = store.vv().get(&me);
            assert!(store
                .mint(keys.signing_key(), Draft::of(&add, HlcPolicy::Now))
                .is_err());
            assert_eq!(store.vv().get(&me), seq, "nothing was minted");
            assert!(store.state().roster.keys(&device).is_none());
            drop(store);
            // ...nor pair such a device in...
            let req = api_tracker_core::mesh::invite::PairRequest {
                name: "small order".into(),
                sign_pub,
                noise_pub,
                seal_pub,
            };
            let inv = v.mesh_invite_create(&master_pw(), None).unwrap();
            let access = v
                .mesh_vault()
                .access_keys(v.connection(), SystemClock.now_ms())
                .unwrap()
                .current;
            let mut store = v.mesh_open_store().unwrap();
            assert!(membership::accept_pairing(
                &mut store,
                keys.signing_key(),
                &inv.token.hash(),
                &req,
                &noise_pub,
                &access,
            )
            .is_err());
            assert!(store.state().roster.keys(&device).is_none());
            drop(store);
            // ...so no share can ever be sealed to its key.
            assert!(v
                .mesh_credential_share(&master_pw(), &cred.id, Recipients::Devices(vec![device]))
                .is_err());
        }
    }
    let shares_after: i64 = v
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM mesh_items WHERE kind = 'share.sealed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(shares_after, shares_before);
}
