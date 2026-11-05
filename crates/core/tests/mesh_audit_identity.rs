//! Regression tests for the 2026-11-03 mesh audit, persistence and identity
//! track (findings MI-1 to MI-9, `docs/mesh/audit/2026-11-03`). Real vaults
//! in temp directories, paired with core's own pairing steps (no network).
//! Every credential value is an unmistakably fake canary.

mod common;

use api_tracker_core::backup;
use api_tracker_core::crypto::{self, aad, KdfParams};
use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::dot::MarkerNonce;
use api_tracker_core::mesh::identity;
use api_tracker_core::mesh::kinds::MeshSetting;
use api_tracker_core::mesh::marker::{self, MarkerContents, MarkerRemoval, MarkerStatus};
use api_tracker_core::mesh::membership::{self, PendingIdentity};
use api_tracker_core::mesh::proto::{Action, Frame, Limits, Session};
use api_tracker_core::mesh::share::Recipients;
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::{Draft, HlcPolicy, MeshStore};
use api_tracker_core::mesh::{DeviceId, MeshError};
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, AddCredential, UnlockedVault, VaultPaths};
use base64::Engine;
use common::{add_project, master_pw, new_vault};
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use tempfile::TempDir;

const CANARY: &str = "sk-test-FAKE-audit-canary-3c9e1a7f5b2d4086";

struct Dev {
    _dir: TempDir,
    paths: VaultPaths,
    v: UnlockedVault,
    app: String,
}

fn dev() -> Dev {
    let (dir, paths, mut v) = new_vault();
    let app = add_project(&mut v, "app").id;
    Dev {
        _dir: dir,
        paths,
        v,
        app,
    }
}

fn store(d: &Dev) -> SqliteStore {
    d.v.mesh_open_store().unwrap()
}

fn id(d: &Dev) -> DeviceId {
    store(d).self_id()
}

fn drafts(prefix: &str, n: usize) -> Vec<Draft> {
    (0..n)
        .map(|i| {
            Draft::of(
                &MeshSetting {
                    name: format!("audit.{prefix}{i}"),
                    value: serde_json::json!(i),
                },
                HlcPolicy::Now,
            )
        })
        .collect()
}

fn marker_of(v: &UnlockedVault) -> MarkerStatus {
    v.mesh_status().unwrap().detail.unwrap().marker
}

/// One complete session between two stores, applying commits.
fn exchange(a: &mut SqliteStore, b: &mut SqliteStore) {
    let mut sa = Session::new(Limits::default(), Some(b.self_id()));
    let mut sb = Session::new(Limits::default(), Some(a.self_id()));
    let (mut to_a, mut to_b): (Vec<Frame>, Vec<Frame>) = (Vec::new(), Vec::new());
    let route = |acts: Vec<Action>, out: &mut Vec<Frame>, s: &mut SqliteStore| {
        for act in acts {
            match act {
                Action::Send(f) => out.push(f),
                Action::Commit(batch) => {
                    s.commit(batch).unwrap();
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
            let acts = sa.on_frame(f, &*a);
            route(acts, &mut to_b, a);
        }
    }
    assert!(sa.is_closed() && sb.is_closed());
}

fn sync(a: &Dev, b: &Dev) {
    exchange(&mut store(a), &mut store(b));
}

/// `b` joins `a`'s mesh with core's pairing steps.
fn join(a: &Dev, b: &Dev, name: &str) {
    let inv = a.v.mesh_invite_create(&master_pw(), None).unwrap();
    let pending = PendingIdentity::generate(name).unwrap();
    let req = pending.request();
    let access =
        a.v.mesh_vault()
            .access_keys(a.v.connection(), SystemClock.now_ms())
            .unwrap()
            .current;
    let keys = a.v.mesh_keys().unwrap();
    let mut sa = store(a);
    let accept = membership::accept_pairing(
        &mut sa,
        keys.signing_key(),
        &inv.token.hash(),
        &req,
        &req.noise_pub,
        &access,
    )
    .unwrap();
    b.v.mesh_join(&pending, &accept).unwrap();
    sync(a, b);
}

fn pair() -> (Dev, Dev) {
    let (a, b) = (dev(), dev());
    a.v.mesh_init("dev-a").unwrap();
    join(&a, &b, "dev-b");
    sync(&a, &b);
    (a, b)
}

fn epoch(v: &UnlockedVault) -> u32 {
    identity::self_info(v.connection())
        .unwrap()
        .unwrap()
        .access_key_epoch
}

fn pragma(conn: &Connection, name: &str) -> i64 {
    conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))
        .unwrap()
}

// ------------------------------------------------------------------ MI-1

/// A mint batch spanning several marker blocks whose transaction rolls back
/// (the publisher's conflict check, a crash, a full disk) leaves the
/// database exactly where it was: the identity must still be trusted.
#[test]
fn a_failed_mint_batch_spanning_blocks_keeps_the_identity_ok() {
    let d = dev();
    d.v.mesh_init("dev-a").unwrap();
    let keys = d.v.mesh_keys().unwrap();
    let mut s = store(&d);
    let before = s.vv().get(&s.self_id());
    let r = s.mint_batch(keys.signing_key(), drafts("a", 200), |_| {
        Err(MeshError::Storage("simulated publish conflict"))
    });
    assert!(r.is_err());
    assert_eq!(s.vv().get(&s.self_id()), before, "nothing committed");
    drop(s);
    assert_eq!(marker_of(&d.v), MarkerStatus::Ok);
    let fresh = store(&d);
    assert_eq!(identity::preflight(&fresh), Ok(()));
    drop(fresh);
    // The identity keeps minting, a large batch included.
    let mut s = store(&d);
    s.mint_batch(keys.signing_key(), drafts("b", 200), |_| Ok(()))
        .unwrap();
    assert_eq!(s.vv().get(&s.self_id()), before + 200);
    assert_eq!(s.marker_status().unwrap(), MarkerStatus::Ok);
}

/// The same failure in one process (a CLI publish) must not stop another
/// store on the same database (the node) once it passes its cached mark.
#[test]
fn a_failed_mint_batch_in_another_store_never_stops_this_one() {
    let d = dev();
    d.v.mesh_init("dev-a").unwrap();
    let keys = d.v.mesh_keys().unwrap();
    let mut node = store(&d);
    let mut cli = store(&d);
    node.mint(keys.signing_key(), drafts("n", 1).remove(0))
        .unwrap();
    assert!(cli
        .mint_batch(keys.signing_key(), drafts("c", 300), |_| {
            Err(MeshError::Storage("simulated publish conflict"))
        })
        .is_err());
    for (i, draft) in drafts("m", 200).into_iter().enumerate() {
        if let Err(e) = node.mint(keys.signing_key(), draft) {
            panic!("the node's mint {i} was refused: {e}");
        }
    }
    assert_eq!(node.marker_status().unwrap(), MarkerStatus::Ok);
    drop((node, cli));
    assert_eq!(marker_of(&d.v), MarkerStatus::Ok);
}

/// Detection is not weakened: a database rolled back past a committed
/// multi-block batch is still refused.
#[test]
fn a_rollback_past_a_committed_multi_block_batch_is_still_detected() {
    let d = dev();
    d.v.mesh_init("dev-a").unwrap();
    let keys = d.v.mesh_keys().unwrap();
    let db_file = d.paths.db_path();
    let snapshot = d._dir.path().join("old.db");
    {
        let s = store(&d);
        s.connection()
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        std::fs::copy(&db_file, &snapshot).unwrap();
    }
    let mut s = store(&d);
    s.mint_batch(keys.signing_key(), drafts("a", 200), |_| Ok(()))
        .unwrap();
    s.mint(keys.signing_key(), drafts("b", 1).remove(0))
        .unwrap();
    drop(s);
    let paths = d.paths.clone();
    let Dev { v, _dir, .. } = d;
    drop(v);
    for side in ["vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(paths.data_dir.join(side));
    }
    std::fs::copy(&snapshot, &db_file).unwrap();
    let v = vault::unlock_vault(&paths, &master_pw()).unwrap();
    assert_eq!(marker_of(&v), MarkerStatus::RolledBack);
    let mut back = v.mesh_open_store().unwrap();
    assert!(identity::preflight(&back).is_err());
    assert!(matches!(
        back.mint(keys.signing_key(), drafts("c", 1).remove(0)),
        Err(MeshError::IdentityMismatch(_))
    ));
}

// ------------------------------------------------------------------ MI-2

/// `mesh leave` is the documented recovery for an untrusted identity, so it
/// must work exactly then: the self-removal cannot be minted, the local wipe
/// still happens.
#[test]
fn leave_succeeds_on_a_missing_mismatched_or_rolled_back_marker() {
    type Break = fn(&Dev);
    let cases: [(&str, Break); 4] = [
        ("missing", |d| {
            std::fs::remove_file(marker::marker_path(&d.paths.data_dir)).unwrap()
        }),
        ("mismatched", |d| {
            marker::write(
                &d.paths.data_dir,
                &MarkerContents::new(id(d), MarkerNonce::from_bytes([9; 16]), 64),
            )
            .unwrap()
        }),
        ("rolled back", |d| {
            let nonce = marker::read(&d.paths.data_dir)
                .unwrap()
                .unwrap()
                .marker_nonce;
            marker::write(
                &d.paths.data_dir,
                &MarkerContents::new(id(d), nonce, 10_000),
            )
            .unwrap()
        }),
        ("unreadable", |d| {
            std::fs::write(marker::marker_path(&d.paths.data_dir), b"{not json").unwrap()
        }),
    ];
    for (what, spoil) in cases {
        let d = dev();
        d.v.mesh_init("dev-a").unwrap();
        spoil(&d);
        // `status` reports the problem instead of failing.
        let st =
            d.v.mesh_status()
                .unwrap_or_else(|e| panic!("{what}: status failed: {e}"));
        let detail = st.detail.unwrap();
        assert_ne!(detail.marker, MarkerStatus::Ok, "{what}");
        assert!(detail.marker_problem.is_some(), "{what}");
        if what == "unreadable" {
            assert_eq!(detail.marker, MarkerStatus::Unreadable);
        }
        let mut delivered_called = false;
        let left = d.v.mesh_leave(&master_pw(), &mut |_| {
            delivered_called = true;
            false
        });
        let report = left.unwrap_or_else(|e| panic!("{what}: leave failed: {e}"));
        assert!(!report.delivered, "{what}");
        assert!(!report.announced, "{what}: nothing was minted");
        assert!(report.not_announced_because.is_some(), "{what}");
        assert!(!delivered_called, "{what}: nothing to deliver");
        assert!(!d.v.mesh_status().unwrap().initialized, "{what}");
        if what == "unreadable" {
            // Not ours to delete: it names nothing readable.
            assert_eq!(report.wipe.marker, MarkerRemoval::LeftInPlace);
        } else {
            assert!(marker::read(&d.paths.data_dir).unwrap().is_none(), "{what}");
        }
        // And the device can start over.
        d.v.mesh_init("dev-a2").unwrap();
        assert_eq!(marker_of(&d.v), MarkerStatus::Ok, "{what}");
    }
}

/// A rollback hold (a peer holds this device's own items past what the
/// database has) also refuses every mint; leave still wipes.
#[test]
fn leave_succeeds_under_a_rollback_hold() {
    let (a, b) = pair();
    let mut sb = store(&b);
    let held = sb.vv().get(&sb.self_id()) + 50;
    sb.hold_minting(id(&a), held).unwrap();
    assert!(sb.rollback_hold().is_some());
    drop(sb);
    let report = b.v.mesh_leave(&master_pw(), &mut |_| false).unwrap();
    assert!(!report.delivered);
    assert!(!report.announced);
    assert!(report.not_announced_because.unwrap().contains("own items"));
    assert!(!b.v.mesh_status().unwrap().initialized);
    assert!(marker::read(&b.paths.data_dir).unwrap().is_none());
}

// ------------------------------------------------------------ MI-3, MI-4

/// Decrypt a backup file with the public primitives: `(file, payload)`.
fn open_backup(
    path: &std::path::Path,
    pw: &SecretString,
) -> (serde_json::Value, serde_json::Value) {
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let kdf: KdfParams = serde_json::from_value(file["kdf"].clone()).unwrap();
    let salt = hex::decode(file["salt_hex"].as_str().unwrap()).unwrap();
    let key = crypto::derive_key(pw, &salt, &kdf).unwrap();
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(file["payload_b64"].as_str().unwrap())
        .unwrap();
    let vault_id = file["vault_id"].as_str().unwrap().to_owned();
    let plain = crypto::decrypt(&key, &aad::backup_v2(&vault_id), &envelope, "test").unwrap();
    let payload = serde_json::from_slice(plain.expose()).unwrap();
    (file, payload)
}

/// Re-encrypt `payload` into `file` (same password and salt) at `path`.
fn seal_backup(
    path: &std::path::Path,
    pw: &SecretString,
    mut file: serde_json::Value,
    payload: &serde_json::Value,
) {
    let kdf: KdfParams = serde_json::from_value(file["kdf"].clone()).unwrap();
    let salt = hex::decode(file["salt_hex"].as_str().unwrap()).unwrap();
    let key = crypto::derive_key(pw, &salt, &kdf).unwrap();
    let vault_id = file["vault_id"].as_str().unwrap().to_owned();
    let envelope = crypto::encrypt(
        &key,
        &aad::backup_v2(&vault_id),
        &serde_json::to_vec(payload).unwrap(),
    )
    .unwrap();
    file["payload_b64"] = base64::engine::general_purpose::STANDARD
        .encode(envelope)
        .into();
    std::fs::write(path, serde_json::to_string(&file).unwrap()).unwrap();
}

/// Every `mesh_*` table of `conn`, exported the way a v2 backup from an
/// older build did (externally tagged cells).
fn export_mesh_tables(conn: &Connection) -> Vec<serde_json::Value> {
    let names: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name LIKE 'mesh\\_%' ESCAPE '\\' ORDER BY name",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut st = conn.prepare(&format!("SELECT * FROM \"{name}\"")).unwrap();
            let columns: Vec<String> = st.column_names().iter().map(|c| c.to_string()).collect();
            let n = columns.len();
            let rows: Vec<serde_json::Value> = st
                .query_map([], |r| {
                    Ok((0..n)
                        .map(|i| match r.get_ref(i).unwrap() {
                            ValueRef::Null => serde_json::json!("Null"),
                            ValueRef::Integer(v) => serde_json::json!({ "Int": v }),
                            ValueRef::Real(v) => serde_json::json!({ "Real": v }),
                            ValueRef::Text(t) => {
                                serde_json::json!({ "Text": std::str::from_utf8(t).unwrap() })
                            }
                            ValueRef::Blob(b) => serde_json::json!({
                                "Blob": base64::engine::general_purpose::STANDARD.encode(b)
                            }),
                        })
                        .collect::<Vec<_>>()
                        .into())
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            serde_json::json!({ "name": name, "columns": columns, "rows": rows })
        })
        .collect()
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |r| {
        r.get(0)
    })
    .unwrap()
}

/// A vault in a mesh with an invite (its encrypted psk) and a peer.
fn mesh_vault_with_secrets() -> Dev {
    let d = dev();
    d.v.mesh_init("source-device").unwrap();
    d.v.mesh_invite_create(&master_pw(), Some(5)).unwrap();
    d.v.mesh_peer_add("127.0.0.1:7420").unwrap();
    d
}

/// Backups carry no mesh row: not the wrapped identity keys, not the access
/// keys, not the invites' pairing psks, not the items (MESH-SI-5: a
/// restored vault is a copy and must pair again, so nothing in them is ever
/// used).
#[test]
fn backup_payload_carries_no_mesh_rows() {
    let d = mesh_vault_with_secrets();
    for t in [
        "mesh_self",
        "mesh_access_keys",
        "mesh_invites",
        "mesh_items",
    ] {
        assert!(count(d.v.connection(), t) > 0, "{t} is populated");
    }
    let pw = SecretString::from("audit-backup-password-01");
    let file = d._dir.path().join("a.backup");
    backup::create_backup(&d.v, &file, &pw, false).unwrap();
    let (_, payload) = open_backup(&file, &pw);
    let mesh: Vec<&str> = payload["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .filter(|n| n.starts_with("mesh_"))
        .collect();
    assert!(mesh.is_empty(), "the backup carries {mesh:?}");
    // Only the device id travels, so a restore can say the copy must pair
    // again and remove a marker naming it.
    assert_eq!(payload["mesh_device"], serde_json::json!(id(&d).to_hex()));
    // The rest of the vault is still there.
    assert!(payload["tables"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "projects"));

    // Restored over the source itself: nothing of the mesh comes back, the
    // identity it discarded is reported and its marker removed.
    let source = id(&d);
    let Dev { v, paths, _dir, .. } = d;
    drop(v);
    let info = backup::restore_backup(&file, &pw, &paths, true).unwrap();
    let wipe = info.mesh_wipe.unwrap();
    assert_eq!(wipe.identity, Some(source));
    assert_eq!(wipe.rows_deleted, 0);
    assert_eq!(wipe.marker, MarkerRemoval::Removed);
    assert!(marker::read(&paths.data_dir).unwrap().is_none());
    let restored = vault::unlock_vault(&paths, &master_pw()).unwrap();
    assert!(!restored.mesh_status().unwrap().initialized);
}

/// A backup made by an older build still holds mesh rows. Restore never
/// imports them, so no crash or error between import, migration and wipe can
/// leave the backed-up identity live: a row that could not even be inserted
/// (a CHECK violation) does not stop the restore, because nothing tries.
#[test]
fn restore_never_imports_mesh_rows_from_an_older_backup() {
    let d = mesh_vault_with_secrets();
    let source = id(&d);
    let pw = SecretString::from("audit-backup-password-02");
    let file = d._dir.path().join("old.backup");
    backup::create_backup(&d.v, &file, &pw, false).unwrap();
    let (header, mut payload) = open_backup(&file, &pw);
    let mut tables: Vec<serde_json::Value> = payload["tables"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| !t["name"].as_str().unwrap().starts_with("mesh_"))
        .cloned()
        .collect();
    let mut mesh = export_mesh_tables(d.v.connection());
    let mesh_rows: usize = mesh
        .iter()
        .map(|t| t["rows"].as_array().unwrap().len())
        .sum();
    // An insert of this row would fail its CHECK (`source` is an enum).
    let peers = mesh.iter_mut().find(|t| t["name"] == "mesh_peers").unwrap();
    let mut poison = peers["rows"][0].clone();
    let cols: Vec<String> = serde_json::from_value(peers["columns"].clone()).unwrap();
    poison[cols.iter().position(|c| c == "addr").unwrap()] =
        serde_json::json!({ "Text": "127.0.0.1:7999" });
    poison[cols.iter().position(|c| c == "source").unwrap()] =
        serde_json::json!({ "Text": "not-a-source" });
    peers["rows"].as_array_mut().unwrap().push(poison);
    tables.extend(mesh);
    payload["tables"] = tables.into();
    // Older builds wrote no `mesh_device`.
    payload.as_object_mut().unwrap().remove("mesh_device");
    seal_backup(&file, &pw, header, &payload);

    // Into a fresh directory.
    let target = VaultPaths::new(d._dir.path().join("restored"));
    let info = backup::restore_backup(&file, &pw, &target, false).unwrap();
    let wipe = info.mesh_wipe.unwrap();
    assert_eq!(wipe.identity, Some(source), "the identity it discarded");
    assert!(
        wipe.rows_deleted as usize > mesh_rows,
        "every mesh row is reported"
    );
    assert_eq!(wipe.marker, MarkerRemoval::Absent);
    let restored = vault::unlock_vault(&target, &master_pw()).unwrap();
    assert!(!restored.mesh_status().unwrap().initialized);
    for t in [
        "mesh_self",
        "mesh_access_keys",
        "mesh_invites",
        "mesh_items",
        "mesh_peers",
    ] {
        assert_eq!(count(restored.connection(), t), 0, "{t} was imported");
    }
    drop(restored);

    // Over the source itself: its marker names the discarded identity.
    let Dev { v, paths, _dir, .. } = d;
    drop(v);
    let info = backup::restore_backup(&file, &pw, &paths, true).unwrap();
    assert_eq!(info.mesh_wipe.unwrap().marker, MarkerRemoval::Removed);
    assert!(marker::read(&paths.data_dir).unwrap().is_none());
}

// ------------------------------------------------------------------ MI-5

/// A removal whose access-key rotation fails must not leave the device
/// removed with the old key still current: the retry completes both.
#[test]
fn a_failed_rotation_after_removal_is_completed_by_a_retry() {
    let (a, b) = pair();
    let before = epoch(&a.v);
    let target = id(&b).to_hex();
    a.v.connection()
        .execute_batch(
            "CREATE TRIGGER audit_fail_rotation BEFORE INSERT ON mesh_access_keys
             BEGIN SELECT RAISE(ABORT, 'injected rotation failure'); END;",
        )
        .unwrap();
    assert!(a.v.mesh_device_remove(&master_pw(), &target).is_err());
    // Nothing half-done: not removed, key not rotated.
    assert!(!store(&a).state().roster.is_removed(&id(&b)));
    assert_eq!(epoch(&a.v), before);
    a.v.connection()
        .execute_batch("DROP TRIGGER audit_fail_rotation")
        .unwrap();
    let (removed, new_epoch) =
        a.v.mesh_device_remove(&master_pw(), &target)
            .expect("the retry completes the removal");
    assert_eq!(removed, id(&b));
    assert_eq!(new_epoch, before + 1);
    assert_eq!(epoch(&a.v), before + 1);
    assert!(store(&a).state().roster.is_removed(&id(&b)));
    // One removal item, not two.
    let removals: i64 =
        a.v.connection()
            .query_row(
                "SELECT COUNT(*) FROM mesh_items WHERE kind = 'roster.remove'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(removals, 1);
}

// ------------------------------------------------------------------ MI-8

/// Deleting a credential would cascade away this device's record of its
/// shares and leave them live and unrevocable from here: refused until they
/// are revoked.
#[test]
fn deleting_a_credential_with_live_shares_is_refused_until_they_are_revoked() {
    let (mut a, b) = pair();
    a.v.mesh_project_share(&a.app).unwrap();
    sync(&a, &b);
    let app = a.app.clone();
    let cred =
        a.v.add_credential(AddCredential {
            project: app,
            provider: "openai".into(),
            name: "OPENAI_API_KEY".into(),
            environment: Environment::Development,
            value: SecretString::from(CANARY),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap()
        .0
        .id;
    a.v.mesh_credential_share(&master_pw(), &cred, Recipients::Devices(vec![id(&b)]))
        .unwrap();
    let err =
        a.v.delete_credential(&cred, &master_pw())
            .expect_err("a credential with live shares is not deleted");
    let msg = err.to_string();
    assert!(msg.contains("mesh credential revoke --credential"), "{msg}");
    assert!(!msg.contains(CANARY));
    assert!(a.v.get_credential(&cred).is_ok(), "still there");
    a.v.mesh_credential_revoke(&cred).unwrap();
    a.v.delete_credential(&cred, &master_pw()).unwrap();
}

// ------------------------------------------------------------------ MI-9

/// Every connection that writes mesh state durably uses F_FULLFSYNC on
/// macOS (the pragma is recorded, and returned, on every platform).
#[test]
fn every_mesh_writing_connection_uses_fullfsync() {
    let a = dev();
    a.v.mesh_init("dev-a").unwrap();
    assert_eq!(pragma(a.v.connection(), "fullfsync"), 1, "init");
    assert_eq!(pragma(a.v.connection(), "synchronous"), 2, "init (FULL)");
    assert_eq!(pragma(store(&a).connection(), "fullfsync"), 1, "store");
    let b = dev();
    join(&a, &b, "dev-b");
    assert_eq!(pragma(b.v.connection(), "fullfsync"), 1, "join");
    // The wipe of `mesh leave`, on a connection that never wrote mesh state.
    let fresh = vault::unlock_vault(&b.paths, &master_pw()).unwrap();
    assert_eq!(pragma(fresh.connection(), "fullfsync"), 0);
    let report = fresh.mesh_leave(&master_pw(), &mut |_| false).unwrap();
    assert!(report.announced && report.not_announced_because.is_none());
    assert_eq!(pragma(fresh.connection(), "fullfsync"), 1, "leave wipe");
}
