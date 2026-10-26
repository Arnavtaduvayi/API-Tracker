//! Tethra Mesh foundations, across modules (Increment 01, ADR 0031).
//!
//! Unit tests in `crates/core/src/mesh/**` prove each piece; these prove the
//! pieces compose the way PROTOCOL.md says they do, with real Ed25519 keys:
//! the ingest checks in order, exhaustive tamper detection, roster-driven
//! verification and admission, opaque unknown kinds, and that no key, token
//! or sealed byte leaks through `Debug`, `Display` or an error message.
//!
//! Every key here is generated per test or is an unmistakably fake
//! repeated-byte pattern.

use api_tracker_core::mesh::codec::{encode_body, ItemBody, MAX_ITEM_BYTES};
use api_tracker_core::mesh::crdt::lww_map::{LwwMap, LwwValue};
use api_tracker_core::mesh::crdt::roster::{AddRecord, Roster};
use api_tracker_core::mesh::crdt::SwEntry;
use api_tracker_core::mesh::dot::{DeviceId, MeshId, MeshProjectId};
use api_tracker_core::mesh::hlc::{Hlc, HlcClock};
use api_tracker_core::mesh::item::{ItemHash, SignedItem};
use api_tracker_core::mesh::kinds::{
    names, DeviceInfo, ItemKind, ProjectMeta, RosterAdd, RosterRemove, TypedItem,
};
use api_tracker_core::mesh::sign::{PublicKeyBytes, SigningKeyPair};
use api_tracker_core::mesh::{clock::ManualClock, MeshError};
use api_tracker_core::CoreError;
use serde_json::json;
use std::sync::Arc;

/// Unmistakably fake secret key material.
const FAKE_SECRET: [u8; 32] = [0x5A; 32];

/// One device: identity, keys, its own seq counter and HLC.
struct Device {
    id: DeviceId,
    key: SigningKeyPair,
    next_seq: u64,
    hlc: HlcClock<Arc<ManualClock>>,
}

impl Device {
    fn new(clock: &Arc<ManualClock>) -> Self {
        Self {
            id: DeviceId::random(),
            key: SigningKeyPair::generate(),
            next_seq: 0,
            hlc: HlcClock::new(clock.clone()),
        }
    }

    fn mint<K: ItemKind>(&mut self, mesh: MeshId, value: &K) -> SignedItem {
        self.next_seq += 1;
        let body = value.to_body(mesh, self.id, self.next_seq, self.hlc.now());
        SignedItem::sign(&body, &self.key).unwrap()
    }

    fn roster_add_of(&self, target: &Device) -> RosterAdd {
        RosterAdd {
            device: target.id,
            name: "test device".into(),
            sign_pub: target.key.public_key(),
            noise_pub: PublicKeyBytes([0x01; 32]),
            seal_pub: PublicKeyBytes([0x02; 32]),
            added_by: self.id,
        }
    }
}

/// The ingest checks of PROTOCOL.md §3.3, in order, against a roster: size,
/// parse, mesh, origin known, signature. The genesis self-add is the one
/// item verified with a key it carries itself.
fn ingest(roster: &Roster, mesh: &MeshId, wire: &[u8]) -> Result<(ItemBody, ItemHash), String> {
    let item = SignedItem::from_wire(wire).map_err(|e| e.to_string())?;
    let unverified = item.decode_unverified().map_err(|e| e.to_string())?;
    if unverified.mesh != *mesh {
        return Err(MeshError::WrongMesh.to_string());
    }
    let sign_pub = match roster.keys(&unverified.origin) {
        Some(k) => k.sign_pub,
        None if unverified.origin == roster.genesis()
            && unverified.kind == names::ROSTER_ADD
            && unverified.key == roster.genesis().to_hex() =>
        {
            RosterAdd::try_from(&unverified)
                .map_err(|e| e.to_string())?
                .sign_pub
        }
        None => return Err("origin is not in the roster".into()),
    };
    let vk = sign_pub.to_verifying_key().map_err(|e| e.to_string())?;
    let body = item.verify_with(&vk, mesh).map_err(|e| e.to_string())?;
    Ok((body, item.hash()))
}

/// Apply a verified roster item.
fn apply_roster(roster: &mut Roster, body: &ItemBody, hash: ItemHash) {
    match TypedItem::parse(body).unwrap() {
        TypedItem::RosterAdd(a) => {
            roster.apply_add(
                body.origin,
                a.device,
                SwEntry::new(body.seq, hash, AddRecord::from(&a)),
            );
        }
        TypedItem::RosterRemove(r) => {
            roster.apply_remove(
                body.origin,
                r.device,
                SwEntry::new(body.seq, hash, r.cutoff_seq),
            );
        }
        _ => {}
    }
}

#[test]
fn flipping_any_byte_of_body_or_signature_fails_verification() {
    let mesh = MeshId::from_bytes([0x11; 16]);
    let key = SigningKeyPair::from_secret_bytes(&FAKE_SECRET);
    let origin = DeviceId::from_bytes([0x22; 16]);
    let body = ItemBody::new(
        mesh,
        origin,
        1,
        Hlc::new(1_700_000_000_000, 0),
        names::MESH_SETTING,
        "retention_days",
        json!({"value": 30}),
    );
    let item = SignedItem::sign(&body, &key).unwrap();
    let vk = key.verifying_key();
    assert_eq!(item.verify_with(&vk, &mesh).unwrap(), body);

    let wire = item.to_wire();
    for i in 0..wire.len() {
        for mask in [0x01u8, 0x80, 0xFF] {
            let mut tampered = wire.clone();
            tampered[i] ^= mask;
            let result = SignedItem::from_wire(&tampered).and_then(|t| t.verify_with(&vk, &mesh));
            assert!(
                result.is_err(),
                "byte {i} (of {}) ^ {mask:#04x} still verified",
                wire.len()
            );
        }
    }
    // Truncation and extension fail too.
    assert!(SignedItem::from_wire(&wire[..wire.len() - 1])
        .and_then(|t| t.verify_with(&vk, &mesh))
        .is_err());
    let mut longer = wire.clone();
    longer.push(b' ');
    assert!(SignedItem::from_wire(&longer)
        .and_then(|t| t.verify_with(&vk, &mesh))
        .is_err());
}

#[test]
fn wrong_mesh_wrong_key_oversize_and_unknown_field_are_refused() {
    let mesh = MeshId::from_bytes([0x11; 16]);
    let key = SigningKeyPair::generate();
    let origin = DeviceId::random();
    let body = ItemBody::new(
        mesh,
        origin,
        1,
        Hlc::ZERO,
        names::MESH_SETTING,
        "x",
        json!({"value": 1}),
    );
    let item = SignedItem::sign(&body, &key).unwrap();
    assert_eq!(
        item.verify_with(&key.verifying_key(), &MeshId::from_bytes([0x12; 16])),
        Err(MeshError::WrongMesh)
    );
    assert_eq!(
        item.verify_with(&SigningKeyPair::generate().verifying_key(), &mesh),
        Err(MeshError::BadSignature)
    );

    let mut big = body.clone();
    big.payload = json!({"value": "x".repeat(MAX_ITEM_BYTES)});
    assert!(matches!(
        SignedItem::sign(&big, &key),
        Err(MeshError::ItemTooLarge { .. })
    ));

    // An extra envelope field, signed by the right key, is still refused:
    // the envelope is strict even when the signature is good.
    let canonical = String::from_utf8(encode_body(&body).unwrap()).unwrap();
    let extra = canonical.replacen(",\"payload\":", ",\"x\":1,\"payload\":", 1);
    let forged = SignedItem::from_parts(extra.into_bytes(), [0; 64]).unwrap();
    assert!(matches!(
        forged.verify_with(&key.verifying_key(), &mesh),
        Err(MeshError::Malformed(_))
    ));
}

#[test]
fn an_unknown_kind_verifies_and_stays_opaque() {
    let mesh = MeshId::random();
    let key = SigningKeyPair::generate();
    let body = ItemBody::new(
        mesh,
        DeviceId::random(),
        4,
        Hlc::new(5, 0),
        "alert.rule.v9",
        "some/future/key",
        json!({"threshold": 3, "nested": {"z": [1, 2], "a": null}}),
    );
    let item = SignedItem::sign(&body, &key).unwrap();
    let back = SignedItem::from_wire(&item.to_wire()).unwrap();
    let verified = back.verify_with(&key.verifying_key(), &mesh).unwrap();
    assert_eq!(verified, body);
    assert_eq!(TypedItem::parse(&verified).unwrap(), TypedItem::Unknown);
    // The stored bytes are what was received, byte for byte.
    assert_eq!(back.to_wire(), item.to_wire());
}

#[test]
fn roster_built_from_signed_items_drives_verification_and_admission() {
    let clock = Arc::new(ManualClock::new(1_700_000_000_000));
    let mesh = MeshId::random();
    let mut g = Device::new(&clock);
    let mut a = Device::new(&clock);
    let outsider = Device::new(&clock);
    let mut receiver = Roster::new(g.id);

    // The genesis self-add verifies with the key it carries.
    let self_add = g.mint(mesh, &g.roster_add_of(&g));
    let (body, hash) = ingest(&receiver, &mesh, &self_add.to_wire()).unwrap();
    apply_roster(&mut receiver, &body, hash);
    assert!(receiver.is_active(&g.id));

    // A's first item arrives before A is in the roster: refused.
    let project = MeshProjectId::random();
    let meta_a = a.mint(
        mesh,
        &ProjectMeta {
            project,
            name: "renamed by A".into(),
            archived: false,
            merged_into: None,
        },
    );
    assert!(ingest(&receiver, &mesh, &meta_a.to_wire()).is_err());

    // G adds A; now A's items verify.
    let add_a = g.mint(mesh, &g.roster_add_of(&a));
    let (body, hash) = ingest(&receiver, &mesh, &add_a.to_wire()).unwrap();
    apply_roster(&mut receiver, &body, hash);
    assert!(receiver.is_active(&a.id));

    // An outsider's self-made "add" of itself is not a genesis.
    let fake = SignedItem::sign(
        &outsider
            .roster_add_of(&outsider)
            .to_body(mesh, outsider.id, 1, Hlc::ZERO),
        &outsider.key,
    )
    .unwrap();
    assert!(ingest(&receiver, &mesh, &fake.to_wire()).is_err());

    // An item claiming A as origin but signed by G is refused (forged origin).
    let forged_body = DeviceInfo {
        device: a.id,
        name: "forged".into(),
        listen_addrs: vec![],
    }
    .to_body(mesh, a.id, 99, Hlc::ZERO);
    let forged = SignedItem::sign(&forged_body, &g.key).unwrap();
    assert!(ingest(&receiver, &mesh, &forged.to_wire()).is_err());

    // Both write the project's name; the later HLC wins while both count.
    clock.advance(1_000);
    let meta_g = g.mint(
        mesh,
        &ProjectMeta {
            project,
            name: "named by G".into(),
            archived: false,
            merged_into: None,
        },
    );
    let mut names_map: LwwMap<MeshProjectId, String> = LwwMap::new();
    for wire in [meta_a.to_wire(), meta_g.to_wire()] {
        let (body, hash) = ingest(&receiver, &mesh, &wire).unwrap();
        let TypedItem::ProjectMeta(p) = TypedItem::parse(&body).unwrap() else {
            panic!("expected project.meta");
        };
        names_map.insert(
            p.project,
            body.origin,
            SwEntry::new(
                body.seq,
                hash,
                LwwValue {
                    hlc: body.hlc,
                    value: p.name,
                },
            ),
        );
    }
    assert_eq!(
        names_map.value(&project, &receiver).map(String::as_str),
        Some("named by G")
    );

    // A writes again, later: its edit beats G's (local_write_ts).
    clock.advance(1_000);
    let winner = names_map.register(&project).unwrap().winning_hlc(&receiver);
    a.next_seq += 1;
    let body = ProjectMeta {
        project,
        name: "A again".into(),
        archived: false,
        merged_into: None,
    }
    .to_body(mesh, a.id, a.next_seq, a.hlc.local_write_ts(winner));
    let meta_a2 = SignedItem::sign(&body, &a.key).unwrap();
    let (body, hash) = ingest(&receiver, &mesh, &meta_a2.to_wire()).unwrap();
    names_map.insert(
        project,
        body.origin,
        SwEntry::new(
            body.seq,
            hash,
            LwwValue {
                hlc: body.hlc,
                value: "A again".to_string(),
            },
        ),
    );
    assert_eq!(
        names_map.value(&project, &receiver).map(String::as_str),
        Some("A again")
    );

    // G removes A with the cutoff it had seen (A's seq 1). A's later write
    // stops counting and the value falls back to G's; A's items still verify.
    let remove = g.mint(
        mesh,
        &RosterRemove {
            device: a.id,
            cutoff_seq: 1,
        },
    );
    let (body, hash) = ingest(&receiver, &mesh, &remove.to_wire()).unwrap();
    apply_roster(&mut receiver, &body, hash);
    assert!(receiver.is_removed(&a.id) && !receiver.is_active(&a.id));
    assert!(
        ingest(&receiver, &mesh, &meta_a2.to_wire()).is_ok(),
        "still relayed"
    );
    assert_eq!(
        names_map.value(&project, &receiver).map(String::as_str),
        Some("named by G")
    );
}

#[test]
fn no_key_signature_or_sealed_bytes_leak_through_debug_display_or_errors() {
    let key = SigningKeyPair::from_secret_bytes(&FAKE_SECRET);
    let secret_hex = hex::encode(FAKE_SECRET);
    let rendered_key = [format!("{key:?}"), format!("{key:#?}"), format!("{key}")];
    for r in &rendered_key {
        assert!(!r.contains(&secret_hex) && !r.contains("90, 90"), "{r}");
    }

    let mesh = MeshId::from_bytes([0x11; 16]);
    let body = ItemBody::new(
        mesh,
        DeviceId::from_bytes([0x22; 16]),
        1,
        Hlc::ZERO,
        names::SHARE_SEALED,
        "irrelevant",
        json!({"sealed": "RkFLRS1URVNULU5PVC1BLVJFQUwtS0VZLTAwMDAwMQ=="}),
    );
    let item = SignedItem::sign(&body, &key).unwrap();
    let sig_hex = hex::encode(item.sig());
    let item_debug = format!("{item:?}");
    assert!(!item_debug.contains("RkFLRS"), "{item_debug}");
    assert!(!item_debug.contains(&sig_hex[..16]), "{item_debug}");

    // Every verification failure message is static text plus sizes.
    let other = SigningKeyPair::generate();
    let mut errors: Vec<MeshError> =
        vec![item.verify_with(&other.verifying_key(), &mesh).unwrap_err()];
    let mut tampered = item.to_wire();
    tampered[10] ^= 0xFF;
    errors.push(
        SignedItem::from_wire(&tampered)
            .and_then(|t| t.verify_with(&key.verifying_key(), &mesh))
            .unwrap_err(),
    );
    errors.push(SignedItem::from_wire(&vec![b'x'; MAX_ITEM_BYTES + 1]).unwrap_err());
    for e in errors {
        let core: CoreError = e.clone().into();
        for text in [
            e.to_string(),
            format!("{e:?}"),
            core.to_string(),
            format!("{core:?}"),
        ] {
            assert!(!text.contains(&secret_hex), "{text}");
            assert!(!text.contains(&sig_hex[..16]), "{text}");
            assert!(!text.contains("RkFLRS"), "{text}");
        }
        assert!(core.code().starts_with("mesh_"), "{}", core.code());
    }
}
