//! Opt-in credential sharing (Increment 11, ADR 0033). Three real vaults in
//! temp directories, paired with core's own pairing steps and replicated
//! through the sans-IO session (the network path is `api-tracker-mesh`'s:
//! `crates/mesh/tests/share_wire.rs` captures its bytes, and
//! `apps/cli/tests/mesh_cli.rs` drives two real nodes).
//!
//! Every value here is an unmistakably fake canary; the leakage checks scan
//! every table, error and report for it (MESH-SI-6).

mod common;

use api_tracker_core::error::CoreError;
use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::doctor::DoctorOptions;
use api_tracker_core::mesh::dot::{CredentialRef, ShareId};
use api_tracker_core::mesh::kinds::{names, ShareSealed};
use api_tracker_core::mesh::membership::{self, PendingIdentity};
use api_tracker_core::mesh::proto::{Action, Frame, Limits, Session};
use api_tracker_core::mesh::share::{Recipients, ShareRow};
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::{Draft, HlcPolicy, MeshStore};
use api_tracker_core::mesh::{DeviceId, MeshError, MeshId};
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{AddCredential, ImportOptions, UnlockedVault};
use base64::Engine;
use common::{add_project, master_pw, new_vault, PROJECT_PW};
use rusqlite::types::ValueRef;
use tempfile::TempDir;

/// The value shared in these tests: unmistakably fake, and unique enough
/// that finding it anywhere is a leak.
const CANARY: &str = "sk-test-FAKE-mesh-canary-5f1c0e9a7b3d2468";
const CANARY_2: &str = "sk-test-FAKE-mesh-canary-rotated-91d4c7e2";
const WRONG: &str = "not-the-master-password";

struct Dev {
    _dir: TempDir,
    v: UnlockedVault,
    app: String,
}

fn dev() -> Dev {
    let (dir, _paths, mut v) = new_vault();
    let app = add_project(&mut v, "app").id;
    Dev { _dir: dir, v, app }
}

fn id(d: &Dev) -> DeviceId {
    store(d).self_id()
}

fn store(d: &Dev) -> SqliteStore {
    d.v.mesh_open_store().unwrap()
}

fn now() -> u64 {
    SystemClock.now_ms()
}

fn wrong() -> SecretString {
    SecretString::from(WRONG)
}

fn opts(replace: bool) -> ImportOptions {
    ImportOptions {
        replace,
        environment: Environment::Development,
    }
}

/// One complete session between two stores, applying commits. Returns every
/// frame sent, as JSON (the plaintext inside the Noise channel).
fn exchange(a: &mut SqliteStore, b: &mut SqliteStore) -> Vec<String> {
    let mut sa = Session::new(Limits::default(), Some(b.self_id()));
    let mut sb = Session::new(Limits::default(), Some(a.self_id()));
    let (mut to_a, mut to_b): (Vec<Frame>, Vec<Frame>) = (Vec::new(), Vec::new());
    let mut seen = Vec::new();
    let mut route = |acts: Vec<Action>, out: &mut Vec<Frame>, s: &mut SqliteStore| {
        for act in acts {
            match act {
                Action::Send(f) => {
                    seen.push(serde_json::to_string(&f).unwrap());
                    out.push(f)
                }
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
    seen
}

fn sync(a: &Dev, b: &Dev) {
    exchange(&mut store(a), &mut store(b));
}

/// `b` joins `a`'s mesh with core's pairing steps (no network).
fn join(a: &Dev, b: &Dev, name: &str) {
    let inv = a.v.mesh_invite_create(&master_pw(), None).unwrap();
    let pending = PendingIdentity::generate(name).unwrap();
    let req = pending.request();
    let access =
        a.v.mesh_vault()
            .access_keys(a.v.connection(), now())
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

/// A, B and C in one mesh; A's "app" is shared and B's and C's are bound to
/// it; A holds the canary credential in "app".
fn trio() -> (Dev, Dev, Dev, String) {
    let (mut a, b, c) = (dev(), dev(), dev());
    a.v.mesh_init("dev-a").unwrap();
    join(&a, &b, "dev-b");
    join(&a, &c, "dev-c");
    sync(&a, &b);
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    sync(&a, &b);
    sync(&a, &c);
    b.v.mesh_project_bind(&p.to_hex(), &b.app).unwrap();
    c.v.mesh_project_bind(&p.to_hex(), &c.app).unwrap();
    let app = a.app.clone();
    let cred = add_cred(&mut a, &app, "OPENAI_API_KEY", CANARY);
    (a, b, c, cred)
}

fn add_cred(d: &mut Dev, project: &str, name: &str, value: &str) -> String {
    d.v.add_credential(AddCredential {
        project: project.to_owned(),
        provider: "openai".into(),
        name: name.into(),
        environment: Environment::Development,
        value: SecretString::from(value),
        credential_type: None,
        key_created_at: None,
        expires_at: None,
        docs_url: String::new(),
        notes: String::new(),
    })
    .unwrap()
    .0
    .id
}

fn count(v: &UnlockedVault, sql: &str) -> i64 {
    v.connection().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn share_items(v: &UnlockedVault) -> i64 {
    count(
        v,
        "SELECT COUNT(*) FROM mesh_items WHERE kind IN ('share.sealed', 'share.revoke')",
    )
}

fn audit(v: &UnlockedVault, event: &str) -> i64 {
    v.connection()
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event = ?1",
            [event],
            |r| r.get(0),
        )
        .unwrap()
}

fn incoming(d: &Dev) -> Vec<ShareRow> {
    d.v.mesh_shares_list().unwrap().incoming
}

fn devices(ds: &[&Dev]) -> Recipients {
    Recipients::Devices(ds.iter().map(|d| id(d)).collect())
}

/// Every encoding of `secret` a leak could take: raw, lowercase and
/// uppercase hex, base64 (standard and URL-safe, at each of the three
/// alignments) and JSON-escaped.
fn leak_forms(secret: &str) -> Vec<Vec<u8>> {
    let mut out = vec![
        secret.as_bytes().to_vec(),
        hex::encode(secret).into_bytes(),
        hex::encode_upper(secret).into_bytes(),
        serde_json::to_string(secret).unwrap().into_bytes(),
    ];
    for pad in ["", "x", "xx"] {
        for engine in [
            &base64::engine::general_purpose::STANDARD,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            let enc = engine.encode(format!("{pad}{secret}"));
            // Drop the characters that depend on the padding prefix and on
            // what follows: the middle is the same wherever the value sits.
            let inner = &enc[4..enc.len() - 4];
            out.push(inner.as_bytes().to_vec());
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn assert_no_leak(what: &str, hay: &[u8], secret: &str) {
    for form in leak_forms(secret) {
        assert!(
            !contains(hay, &form),
            "{what} holds the value (as {:?})",
            String::from_utf8_lossy(&form)
        );
    }
}

/// Scan every column of every table for the value in any form. The
/// credential's own ciphertext columns are encrypted, so a plaintext match
/// anywhere is a leak.
fn assert_no_plaintext_anywhere(v: &UnlockedVault, secret: &str) {
    let conn = v.connection();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for t in tables {
        let mut st = conn.prepare(&format!("SELECT * FROM \"{t}\"")).unwrap();
        let n = st.column_count();
        let mut rows = st.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..n {
                let bytes: Vec<u8> = match row.get_ref(i).unwrap() {
                    ValueRef::Text(b) | ValueRef::Blob(b) => b.to_vec(),
                    _ => continue,
                };
                assert_no_leak(&format!("table {t} column {i}"), &bytes, secret);
            }
        }
    }
}

fn assert_err_clean(e: &CoreError) {
    let text = format!("{e} {e:?} {e:#}");
    for s in [CANARY, CANARY_2, WRONG] {
        assert_no_leak("an error", text.as_bytes(), s);
    }
}

#[test]
fn share_then_import_round_trip_re_encrypts_under_the_target_project() {
    let (a, mut b, mut c, cred) = trio();
    let receipt =
        a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&b]))
            .unwrap();
    assert_eq!(receipt.recipients.len(), 1);
    assert_eq!(receipt.recipients[0].device_id, id(&b));
    assert_eq!(receipt.recipients[0].device_name.as_deref(), Some("dev-b"));
    assert!(!receipt.all_current);
    assert_eq!(audit(&a.v, "mesh_credential_shared"), 1);
    // The receipt and its JSON carry no value.
    let json = serde_json::to_string(&receipt).unwrap();
    assert_no_leak("the share receipt", json.as_bytes(), CANARY);
    // The frames inside the Noise channel carry the sealed box, never the
    // value (the encrypted wire itself: crates/mesh/tests/share_wire.rs).
    let frames = exchange(&mut store(&a), &mut store(&b));
    assert!(frames.iter().any(|f| f.contains("\"t\":\"Items\"")));
    for f in &frames {
        assert_no_leak("a session frame", f.as_bytes(), CANARY);
    }
    sync(&a, &c);

    // Only B received anything: C holds no share addressed to it.
    let rows = incoming(&b);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(
        (row.credential_name.as_str(), row.provider.as_str()),
        ("OPENAI_API_KEY", "openai")
    );
    assert_eq!(row.sharer, id(&a));
    assert_eq!(row.sharer_name.as_deref(), Some("dev-a"));
    assert!(!row.revoked && row.imported.is_none());
    assert!(incoming(&c).is_empty());
    // C holds the item (items replicate everywhere) but cannot import it.
    let err =
        c.v.mesh_credential_import(&master_pw(), &row.share_id.to_hex(), "app", opts(false))
            .unwrap_err();
    assert!(matches!(err, CoreError::NotFound { .. }), "{err:?}");
    // A lists it as outgoing, with the local credential behind it.
    let out = a.v.mesh_shares_list().unwrap().outgoing;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].local_credential_id.as_deref(), Some(cred.as_str()));
    assert_eq!(out[0].current_value_version, Some(1));

    // Import on B (by an 8-character prefix), into B's own project.
    let prefix = row.share_id.to_hex()[..8].to_owned();
    let got =
        b.v.mesh_credential_import(&master_pw(), &prefix, "app", opts(false))
            .unwrap();
    assert!(!got.replaced);
    assert_eq!(got.sharer, id(&a));
    assert_eq!(got.credential.project_id, b.app);
    assert_eq!(got.credential.name, "OPENAI_API_KEY");
    assert_eq!(got.credential.masked_value, "sk-t…68");
    assert_no_leak(
        "the import receipt",
        serde_json::to_string(&got).unwrap().as_bytes(),
        CANARY,
    );
    assert_no_leak("its Debug", format!("{got:?}").as_bytes(), CANARY);
    // The value is in B's vault, encrypted under B's project key: the
    // normal reveal path decrypts it.
    let revealed =
        b.v.reveal_credential(&got.credential.id, &master_pw())
            .unwrap();
    assert_eq!(revealed.expose(), CANARY);
    assert_eq!(audit(&b.v, "mesh_credential_imported"), 1);
    assert_eq!(count(&b.v, "SELECT COUNT(*) FROM mesh_share_imports"), 1);
    let rows = incoming(&b);
    let imported = rows[0].imported.as_ref().unwrap();
    assert_eq!(imported.credential_id, got.credential.id);
    assert_eq!(imported.project_name, "app");
    // A second import of the same share is refused.
    let err =
        b.v.mesh_credential_import(&master_pw(), &prefix, "app", opts(true))
            .unwrap_err();
    assert!(err.to_string().contains("already imported"), "{err}");

    // Storage canary (MESH-SI-6): nowhere in plaintext on any device, in
    // any table (the item store's sealed bytes included), audit rows
    // included.
    for d in [&a, &b, &c] {
        assert_no_plaintext_anywhere(&d.v, CANARY);
        let doctor = d.v.mesh_doctor(DoctorOptions { rebuild: false }).unwrap();
        assert_no_leak(
            "doctor output",
            format!("{doctor:?} {}", serde_json::to_string(&doctor).unwrap()).as_bytes(),
            CANARY,
        );
        let list = d.v.mesh_shares_list().unwrap();
        assert_no_leak(
            "the share list",
            serde_json::to_string(&list).unwrap().as_bytes(),
            CANARY,
        );
        let status = d.v.mesh_status().unwrap();
        assert_no_leak(
            "mesh status",
            serde_json::to_string(&status).unwrap().as_bytes(),
            CANARY,
        );
    }
    assert_err_clean(&err);
}

#[test]
fn a_wrong_password_on_share_or_import_changes_nothing() {
    let (a, mut b, _c, cred) = trio();
    let err =
        a.v.mesh_credential_share(&wrong(), &cred, Recipients::AllCurrent)
            .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert_err_clean(&err);
    assert_eq!(share_items(&a.v), 0);
    assert_eq!(audit(&a.v, "mesh_credential_shared"), 0);
    assert_eq!(count(&a.v, "SELECT COUNT(*) FROM mesh_share_outgoing"), 0);

    a.v.mesh_credential_share(&master_pw(), &cred, Recipients::AllCurrent)
        .unwrap();
    sync(&a, &b);
    let share = incoming(&b)[0].share_id.to_hex();
    let creds = count(&b.v, "SELECT COUNT(*) FROM credentials");
    let err =
        b.v.mesh_credential_import(&wrong(), &share, "app", opts(false))
            .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert_err_clean(&err);
    assert_eq!(count(&b.v, "SELECT COUNT(*) FROM credentials"), creds);
    assert_eq!(count(&b.v, "SELECT COUNT(*) FROM mesh_share_imports"), 0);
    assert_eq!(audit(&b.v, "mesh_credential_imported"), 0);
}

#[test]
fn a_credential_of_an_unbound_project_cannot_be_shared() {
    let (mut a, _b, _c, _cred) = trio();
    let other = add_project(&mut a.v, "other").id;
    let cred = add_cred(&mut a, &other, "KEY", CANARY);
    let err =
        a.v.mesh_credential_share(&master_pw(), &cred, Recipients::AllCurrent)
            .unwrap_err();
    assert!(
        matches!(err, CoreError::Mesh(MeshError::ProjectNotBound)),
        "{err:?}"
    );
    assert_eq!(err.code(), "mesh_project_not_bound");
    assert_err_clean(&err);
    assert_eq!(share_items(&a.v), 0);
}

#[test]
fn a_locked_password_project_is_refused_and_an_unlocked_one_shares() {
    let (mut a, b, _c, cred) = trio();
    a.v.set_project_password("app", &SecretString::from(PROJECT_PW), &master_pw())
        .unwrap();
    a.v.lock_project("app").unwrap();
    let err =
        a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&b]))
            .unwrap_err();
    assert!(matches!(err, CoreError::ProjectLocked(_)), "{err:?}");
    assert_err_clean(&err);
    assert_eq!(share_items(&a.v), 0);
    a.v.unlock_project("app", &SecretString::from(PROJECT_PW))
        .unwrap();
    a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&b]))
        .unwrap();
    assert_eq!(share_items(&a.v), 1);

    // Importing into a locked project on B is refused the same way, and
    // nothing is recorded.
    let mut b = b;
    sync(&a, &b);
    b.v.set_project_password("app", &SecretString::from(PROJECT_PW), &master_pw())
        .unwrap();
    b.v.lock_project("app").unwrap();
    let share = incoming(&b)[0].share_id.to_hex();
    let err =
        b.v.mesh_credential_import(&master_pw(), &share, "app", opts(false))
            .unwrap_err();
    assert!(matches!(err, CoreError::ProjectLocked(_)), "{err:?}");
    assert_eq!(count(&b.v, "SELECT COUNT(*) FROM mesh_share_imports"), 0);
    b.v.unlock_project("app", &SecretString::from(PROJECT_PW))
        .unwrap();
    let got =
        b.v.mesh_credential_import(&master_pw(), &share, "app", opts(false))
            .unwrap();
    assert_eq!(
        b.v.reveal_credential(&got.credential.id, &master_pw())
            .unwrap()
            .expose(),
        CANARY
    );
}

#[test]
fn recipients_must_be_other_active_devices() {
    let (a, b, c, cred) = trio();
    for bad in [
        Recipients::Devices(vec![id(&a)]),
        Recipients::Devices(vec![DeviceId::from_bytes([0x5a; 16])]),
        Recipients::Devices(Vec::new()),
    ] {
        let err =
            a.v.mesh_credential_share(&master_pw(), &cred, bad)
                .unwrap_err();
        assert!(matches!(err, CoreError::Mesh(_)), "{err:?}");
        assert_err_clean(&err);
    }
    assert_eq!(share_items(&a.v), 0);
    // All current devices: B and C, one item each.
    let r =
        a.v.mesh_credential_share(&master_pw(), &cred, Recipients::AllCurrent)
            .unwrap();
    let mut to: Vec<DeviceId> = r.recipients.iter().map(|s| s.device_id).collect();
    to.sort();
    let mut want = vec![id(&b), id(&c)];
    want.sort();
    assert_eq!(to, want);
    assert!(r.all_current);
}

/// The sealed plaintext, as a sharer writes it (the format ADR 0033 fixes).
#[allow(clippy::too_many_arguments)]
fn plaintext(
    mesh: MeshId,
    share: ShareId,
    name: &str,
    provider: &str,
    version: u64,
    recipient: DeviceId,
    sharer: DeviceId,
    value: &str,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "mesh_id": mesh,
        "share_id": share,
        "credential_name": name,
        "provider": provider,
        "value_version": version,
        "recipient": recipient,
        "sharer": sharer,
        "value": value,
    }))
    .unwrap()
}

/// `signer` mints a `share.sealed` addressed to `to` whose box holds
/// `plain`, with the given envelope.
fn mint_crafted(signer: &Dev, to: &Dev, share: ShareId, name: &str, version: u64, sealed: Vec<u8>) {
    let keys = signer.v.mesh_keys().unwrap();
    let mut s = store(signer);
    let mesh_project = s.state().projects.keys().next().copied().unwrap();
    let item = ShareSealed {
        credential: CredentialRef::random(),
        recipient: id(to),
        share_id: share,
        mesh_project_id: mesh_project,
        credential_name: name.into(),
        provider: "openai".into(),
        value_version: version,
        sealed,
    };
    s.mint(keys.signing_key(), Draft::of(&item, HlcPolicy::Now))
        .unwrap();
}

fn seal_for(to: &Dev, plain: &[u8]) -> Vec<u8> {
    let s = store(to);
    let me = s.self_id();
    let pk = s.state().roster.keys(&me).unwrap().seal_pub;
    crypto_box::PublicKey::from_bytes(pk.0)
        .seal(&mut crypto_box::aead::OsRng, plain)
        .unwrap()
}

#[test]
fn a_member_cannot_plant_a_credential_in_the_name_of_another_device() {
    let (a, b, mut c, cred) = trio();
    let mesh = store(&a).genesis().mesh_id;
    let creds = count(&c.v, "SELECT COUNT(*) FROM credentials");

    // 1. B seals a value of its own to C, claiming A shared it.
    let planted = ShareId::random();
    let plain = plaintext(
        mesh,
        planted,
        "PLANTED",
        "openai",
        1,
        id(&c),
        id(&a),
        CANARY_2,
    );
    mint_crafted(&b, &c, planted, "PLANTED", 1, seal_for(&c, &plain));

    // 2. A shares with C; B, which relays A's items, re-wraps A's genuine
    // box into items of its own: once under A's share id, once under a new
    // one.
    let first =
        a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&c]))
            .unwrap();
    sync(&a, &b);
    let bs = store(&b);
    let genuine = bs
        .state()
        .shares_sealed
        .values(&bs.state().roster)
        .map(|(_, v)| v.clone())
        .find(|v| v.share_id == first.recipients[0].share_id)
        .unwrap();
    drop(bs);
    let rewrapped = ShareId::random();
    mint_crafted(
        &b,
        &c,
        genuine.share_id,
        "OPENAI_API_KEY",
        1,
        genuine.sealed.clone(),
    );
    mint_crafted(
        &b,
        &c,
        rewrapped,
        "OPENAI_API_KEY",
        1,
        genuine.sealed.clone(),
    );
    // A shares again, so its first share id is only B's copy now.
    let second =
        a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&c]))
            .unwrap();
    sync(&a, &c);
    sync(&b, &c);

    let try_import = |c: &mut Dev, share: &ShareId| {
        c.v.mesh_credential_import(&master_pw(), &share.to_hex(), "app", opts(true))
            .unwrap_err()
    };
    for (share, field) in [
        (planted, "sharer"),
        (genuine.share_id, "sharer"),
        (rewrapped, "share id"),
    ] {
        let err = try_import(&mut c, &share);
        assert!(
            matches!(&err, CoreError::Mesh(MeshError::ShareBindingMismatch(f)) if *f == field),
            "{field}: {err:?}"
        );
        assert_eq!(err.code(), "mesh_share_binding_mismatch");
        assert_err_clean(&err);
    }
    // Nothing planted was stored; A's current share imports.
    assert_eq!(count(&c.v, "SELECT COUNT(*) FROM credentials"), creds);
    assert_eq!(count(&c.v, "SELECT COUNT(*) FROM mesh_share_imports"), 0);
    let got =
        c.v.mesh_credential_import(
            &master_pw(),
            &second.recipients[0].share_id.to_hex(),
            "app",
            opts(false),
        )
        .unwrap();
    assert_eq!(
        c.v.reveal_credential(&got.credential.id, &master_pw())
            .unwrap()
            .expose(),
        CANARY
    );
    assert_no_plaintext_anywhere(&c.v, CANARY_2);
}

/// Builds a sealed plaintext for a given envelope share id.
type MakePlain = Box<dyn Fn(ShareId) -> Vec<u8>>;

#[test]
fn each_bound_field_that_disagrees_with_the_envelope_is_refused() {
    let (a, mut b, _c, _cred) = trio();
    let mesh = store(&a).genesis().mesh_id;
    let (me, sharer) = (id(&b), id(&a));
    let other = DeviceId::from_bytes([0x33; 16]);
    let cases: Vec<(&str, MakePlain)> = vec![
        (
            "mesh",
            Box::new(move |s| {
                plaintext(
                    MeshId::from_bytes([7; 16]),
                    s,
                    "K",
                    "openai",
                    1,
                    me,
                    sharer,
                    CANARY_2,
                )
            }),
        ),
        (
            "share id",
            Box::new(move |_| {
                plaintext(
                    mesh,
                    ShareId::random(),
                    "K",
                    "openai",
                    1,
                    me,
                    sharer,
                    CANARY_2,
                )
            }),
        ),
        (
            "recipient",
            Box::new(move |s| plaintext(mesh, s, "K", "openai", 1, other, sharer, CANARY_2)),
        ),
        (
            "sharer",
            Box::new(move |s| plaintext(mesh, s, "K", "openai", 1, me, other, CANARY_2)),
        ),
        (
            "credential name",
            Box::new(move |s| plaintext(mesh, s, "K2", "openai", 1, me, sharer, CANARY_2)),
        ),
        (
            "provider",
            Box::new(move |s| plaintext(mesh, s, "K", "anthropic", 1, me, sharer, CANARY_2)),
        ),
        (
            "value version",
            Box::new(move |s| plaintext(mesh, s, "K", "openai", 2, me, sharer, CANARY_2)),
        ),
        ("contents", Box::new(|_| b"{not json".to_vec())),
    ];
    for (field, make) in cases {
        let share = ShareId::random();
        mint_crafted(&a, &b, share, "K", 1, seal_for(&b, &make(share)));
        sync(&a, &b);
        let err =
            b.v.mesh_credential_import(&master_pw(), &share.to_hex(), "app", opts(true))
                .unwrap_err();
        assert!(
            matches!(&err, CoreError::Mesh(MeshError::ShareBindingMismatch(f)) if *f == field),
            "{field}: {err:?}"
        );
        assert_err_clean(&err);
    }
    // A box sealed to another device's key does not open here.
    let share = ShareId::random();
    let plain = plaintext(mesh, share, "K", "openai", 1, me, sharer, CANARY_2);
    mint_crafted(&a, &b, share, "K", 1, seal_for(&a, &plain));
    sync(&a, &b);
    let err =
        b.v.mesh_credential_import(&master_pw(), &share.to_hex(), "app", opts(true))
            .unwrap_err();
    assert!(
        matches!(err, CoreError::Mesh(MeshError::ShareUnreadable)),
        "{err:?}"
    );
    assert_eq!(count(&b.v, "SELECT COUNT(*) FROM mesh_share_imports"), 0);
    assert_no_plaintext_anywhere(&b.v, CANARY_2);
}

#[test]
fn a_revoked_share_cannot_be_imported_and_a_replay_does_not_bring_it_back() {
    let (a, mut b, c, cred) = trio();
    a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&b]))
        .unwrap();
    sync(&a, &b);
    // C relays the share too, then misses the revoke.
    sync(&b, &c);
    let share = incoming(&b)[0].share_id;
    let revoked = a.v.mesh_share_revoke(&share.to_hex()).unwrap();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].recipient, id(&b));
    assert_eq!(audit(&a.v, "mesh_share_revoked"), 1);
    // Revoking again finds nothing live.
    assert!(a.v.mesh_share_revoke(&share.to_hex()).is_err());
    sync(&a, &b);
    let rows = incoming(&b);
    assert!(rows[0].revoked);
    assert_eq!(rows[0].revoked_by, Some(id(&a)));
    let err =
        b.v.mesh_credential_import(&master_pw(), &share.to_hex(), "app", opts(false))
            .unwrap_err();
    assert!(
        matches!(err, CoreError::Mesh(MeshError::ShareRevoked)),
        "{err:?}"
    );
    // C, which still holds the old share item and not the revoke, exchanges
    // with B: last-writer-wins keeps the revoke on both.
    sync(&c, &b);
    let err =
        b.v.mesh_credential_import(&master_pw(), &share.to_hex(), "app", opts(false))
            .unwrap_err();
    assert!(matches!(err, CoreError::Mesh(MeshError::ShareRevoked)));
    assert!(matches!(
        store(&c)
            .state()
            .share_at(&(revoked[0].credential_ref, id(&b))),
        Some(api_tracker_core::mesh::views::ShareWinner::Revoked { .. })
    ));
    // Sharing again after the revoke wins over it.
    let again =
        a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&b]))
            .unwrap();
    assert_eq!(again.credential_ref, revoked[0].credential_ref);
    sync(&a, &b);
    b.v.mesh_credential_import(
        &master_pw(),
        &again.recipients[0].share_id.to_hex(),
        "app",
        opts(false),
    )
    .unwrap();
    // Revoking by credential covers every live share of it.
    let n = a.v.mesh_credential_revoke(&cred).unwrap();
    assert_eq!(n.len(), 1);
    // B keeps what it imported (ADR 0033): a revoke never deletes it.
    assert_eq!(
        count(
            &b.v,
            "SELECT COUNT(*) FROM credentials WHERE name = 'OPENAI_API_KEY'"
        ),
        1
    );
}

#[test]
fn shares_to_a_removed_device_are_purged_and_not_stored_again() {
    let (a, b, c, cred) = trio();
    a.v.mesh_credential_share(&master_pw(), &cred, Recipients::AllCurrent)
        .unwrap();
    sync(&a, &b);
    sync(&a, &c);
    assert_eq!(share_items(&b.v), 2);
    a.v.mesh_device_remove(&master_pw(), &id(&c).to_hex())
        .unwrap();
    // A forgets C's share at once (views), and collects it from storage.
    assert!(a
        .v
        .mesh_shares_peek()
        .unwrap()
        .outgoing
        .iter()
        .all(|r| r.recipient != id(&c)));
    a.v.mesh_shares_list().unwrap();
    assert_eq!(share_items(&a.v), 1);
    // B learns of the removal; until it purges it still holds C's share.
    sync(&a, &b);
    assert_eq!(share_items(&b.v), 2);
    // An exchange with equal version vectors repairs (the digests differ):
    // A, purging, does not store C's share again.
    sync(&b, &a);
    assert_eq!(share_items(&a.v), 1);
    b.v.mesh_shares_list().unwrap();
    assert_eq!(share_items(&b.v), 1);
    sync(&a, &b);
    assert_eq!(share_items(&a.v), 1);
    assert_eq!(share_items(&b.v), 1);
    // Nothing is offered to the removed device either.
    assert!(a.v.mesh_shares_list().unwrap().reseal_offers.is_empty());
}

#[test]
fn a_new_device_gets_a_reseal_offer_that_does_nothing_without_reauth() {
    let (mut a, b) = (dev(), dev());
    a.v.mesh_init("dev-a").unwrap();
    join(&a, &b, "dev-b");
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    let app = a.app.clone();
    let cred = add_cred(&mut a, &app, "OPENAI_API_KEY", CANARY);
    a.v.mesh_credential_share(&master_pw(), &cred, Recipients::AllCurrent)
        .unwrap();
    assert!(a.v.mesh_shares_list().unwrap().reseal_offers.is_empty());
    let c = dev();
    join(&a, &c, "dev-c");
    let offers = a.v.mesh_shares_list().unwrap().reseal_offers;
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].credential_id, cred);
    assert_eq!(offers[0].new_devices, vec![id(&c)]);
    assert!(offers[0].stale_devices.is_empty());
    // An offer mints nothing by itself; a wrong password mints nothing.
    assert_eq!(share_items(&a.v), 1);
    let err = a.v.mesh_credential_reseal(&wrong(), &cred).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword));
    assert_eq!(share_items(&a.v), 1);
    let r = a.v.mesh_credential_reseal(&master_pw(), &cred).unwrap();
    assert_eq!(
        r.recipients.iter().map(|s| s.device_id).collect::<Vec<_>>(),
        vec![id(&c)]
    );
    assert!(r.all_current, "a reseal keeps the intent");
    assert!(a.v.mesh_shares_list().unwrap().reseal_offers.is_empty());
    assert!(a.v.mesh_credential_reseal(&master_pw(), &cred).is_err());

    // A new value makes both shares stale; the reseal sends the new one.
    a.v.replace_credential_value(&cred, &master_pw(), SecretString::from(CANARY_2))
        .unwrap();
    let offers = a.v.mesh_shares_list().unwrap().reseal_offers;
    let mut stale = offers[0].stale_devices.clone();
    stale.sort();
    let mut want = vec![id(&b), id(&c)];
    want.sort();
    assert_eq!(stale, want);
    assert_eq!(offers[0].current_value_version, 2);
    a.v.mesh_credential_reseal(&master_pw(), &cred).unwrap();
    assert!(a.v.mesh_shares_list().unwrap().reseal_offers.is_empty());
    // An explicit share (not "all current") gets no new-device offer.
    let mut b = b;
    sync(&a, &b);
    b.v.mesh_project_bind(&p.to_hex(), &b.app).unwrap();
    let bapp = b.app.clone();
    let bcred = add_cred(&mut b, &bapp, "B_KEY", "sk-test-FAKE-b-only-0001");
    b.v.mesh_credential_share(&master_pw(), &bcred, devices(&[&a]))
        .unwrap();
    let d = dev();
    join(&a, &d, "dev-d");
    sync(&a, &b);
    assert!(b.v.mesh_shares_list().unwrap().reseal_offers.is_empty());
}

#[test]
fn import_with_replace_versions_the_existing_credential() {
    let (a, mut b, _c, cred) = trio();
    let bapp = b.app.clone();
    let existing = add_cred(&mut b, &bapp, "OPENAI_API_KEY", "sk-test-FAKE-old-b-0001");
    a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&b]))
        .unwrap();
    sync(&a, &b);
    let share = incoming(&b)[0].share_id.to_hex();
    let err =
        b.v.mesh_credential_import(&master_pw(), &share, "app", opts(false))
            .unwrap_err();
    assert!(err.to_string().contains("--replace"), "{err}");
    assert_eq!(count(&b.v, "SELECT COUNT(*) FROM mesh_share_imports"), 0);
    let got =
        b.v.mesh_credential_import(&master_pw(), &share, "app", opts(true))
            .unwrap();
    assert!(got.replaced);
    assert_eq!(got.credential.id, existing);
    assert_eq!(
        b.v.reveal_credential(&existing, &master_pw())
            .unwrap()
            .expose(),
        CANARY
    );
    let history =
        b.v.credential_version_history(&existing, &master_pw())
            .unwrap();
    assert!(history.len() >= 2, "{history:?}");
    assert_eq!(audit(&b.v, "mesh_credential_imported"), 1);
    assert_no_plaintext_anywhere(&b.v, CANARY);
}

#[test]
fn the_share_items_carry_names_but_never_the_value() {
    let (a, b, _c, cred) = trio();
    a.v.mesh_credential_share(&master_pw(), &cred, Recipients::AllCurrent)
        .unwrap();
    sync(&a, &b);
    let s = store(&b);
    let mut n = 0;
    for item in s.all_items().unwrap() {
        let body = item.decode_unverified().unwrap();
        if body.kind == names::SHARE_SEALED {
            n += 1;
            assert_no_leak("a share item", &item.to_wire(), CANARY);
        }
    }
    assert_eq!(n, 2);
}

// ------------------------------------------------- review findings (S+R)

/// Review #1: a revoke ends only the share it names. A revoke of an older
/// share, minted with a later HLC by a device that had not seen the newer
/// share, must not hide the newer one.
#[test]
fn a_revoke_ends_only_the_share_it_names() {
    let (a, b, mut c, cred) = trio();
    let first =
        a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&c]))
            .unwrap();
    sync(&a, &b);
    let x = first.recipients[0].share_id;
    let second =
        a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&c]))
            .unwrap();
    let y = second.recipients[0].share_id;
    // B, which has seen only X, revokes X with an HLC above Y's.
    let y_hlc = store(&a)
        .state()
        .share_winning_hlc(&(first.credential_ref, id(&c)))
        .unwrap();
    {
        let keys = b.v.mesh_keys().unwrap();
        let mut s = store(&b);
        let r = api_tracker_core::mesh::kinds::ShareRevoke {
            credential: first.credential_ref,
            recipient: id(&c),
            share_id: x,
        };
        s.mint(
            keys.signing_key(),
            Draft::of(&r, HlcPolicy::After(Some(y_hlc))),
        )
        .unwrap();
    }
    sync(&a, &b);
    sync(&b, &c);
    sync(&a, &c);
    let rows = incoming(&c);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].share_id, y);
    assert!(!rows[0].revoked, "a revoke of X does not end Y");
    c.v.mesh_credential_import(&master_pw(), &y.to_hex(), "app", opts(false))
        .unwrap();
    // And A still lists Y as its live share.
    let out = a.v.mesh_shares_list().unwrap().outgoing;
    assert!(out.iter().any(|r| r.share_id == y && !r.revoked), "{out:?}");
}

/// Review #2: a device revokes only shares it made, never a share between
/// two other devices that it merely relays.
#[test]
fn a_device_revokes_only_shares_it_made() {
    let (a, b, c, cred) = trio();
    let r =
        a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&c]))
            .unwrap();
    sync(&a, &b);
    sync(&a, &c);
    let prefix = r.recipients[0].share_id.to_hex()[..8].to_owned();
    for d in [&b, &c] {
        let err = d.v.mesh_share_revoke(&prefix).unwrap_err();
        assert!(matches!(err, CoreError::NotFound { .. }), "{err:?}");
    }
    assert_eq!(
        count(
            &b.v,
            "SELECT COUNT(*) FROM mesh_items WHERE kind = 'share.revoke'"
        ),
        0
    );
    assert_eq!(a.v.mesh_share_revoke(&prefix).unwrap().len(), 1);
}

/// Review #3: a share made by a device that has since been removed (lost or
/// stolen) is listed as such and cannot be imported.
#[test]
fn a_share_from_a_since_removed_device_cannot_be_imported() {
    let (a, mut b, mut c, _cred) = trio();
    let bapp = b.app.clone();
    let bcred = add_cred(&mut b, &bapp, "STRIPE_SECRET_KEY", CANARY_2);
    b.v.mesh_credential_share(&master_pw(), &bcred, devices(&[&c]))
        .unwrap();
    sync(&b, &c);
    // A has seen the share, so it is within B's removal cutoff (a share
    // above the cutoff is excluded by admission already).
    sync(&b, &a);
    let b_id = id(&b);
    a.v.mesh_device_remove(&master_pw(), &b_id.to_hex())
        .unwrap();
    sync(&a, &c);
    let rows = incoming(&c);
    let row = rows.iter().find(|r| r.sharer == b_id).unwrap();
    assert!(!row.sharer_active, "{row:?}");
    let err =
        c.v.mesh_credential_import(&master_pw(), &row.share_id.to_hex(), "app", opts(false))
            .unwrap_err();
    assert!(
        matches!(err, CoreError::Mesh(MeshError::ShareFromRemovedDevice)),
        "{err:?}"
    );
    assert_eq!(count(&c.v, "SELECT COUNT(*) FROM mesh_share_imports"), 0);
    assert_no_plaintext_anywhere(&c.v, CANARY_2);
}

/// Review #6: another device's item at this device's share key does not hide
/// this device's share from its own list or its reseal offer.
#[test]
fn another_devices_item_at_my_share_key_does_not_hide_my_share() {
    let (a, b, mut c, cred) = trio();
    let r =
        a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&c]))
            .unwrap();
    sync(&a, &b);
    let key = (r.credential_ref, id(&c));
    let hlc = store(&b).state().share_winning_hlc(&key).unwrap();
    {
        let keys = b.v.mesh_keys().unwrap();
        let mut s = store(&b);
        let mesh_project = r.mesh_project_id;
        let item = ShareSealed {
            credential: r.credential_ref,
            recipient: id(&c),
            share_id: ShareId::random(),
            mesh_project_id: mesh_project,
            credential_name: "OPENAI_API_KEY".into(),
            provider: "openai".into(),
            value_version: 1,
            sealed: vec![1; 64],
        };
        s.mint(
            keys.signing_key(),
            Draft::of(&item, HlcPolicy::After(Some(hlc))),
        )
        .unwrap();
    }
    sync(&b, &a);
    let out = a.v.mesh_shares_list().unwrap();
    let mine = out
        .outgoing
        .iter()
        .find(|row| row.share_id == r.recipients[0].share_id)
        .expect("A still lists its share");
    assert_eq!(mine.superseded_by, Some(id(&b)));
    let offer = out
        .reseal_offers
        .iter()
        .find(|o| o.credential_id == cred)
        .expect("a reseal offer for C");
    assert_eq!(offer.stale_devices, vec![id(&c)]);
    let again = a.v.mesh_credential_reseal(&master_pw(), &cred).unwrap();
    sync(&a, &c);
    sync(&b, &c);
    c.v.mesh_credential_import(
        &master_pw(),
        &again.recipients[0].share_id.to_hex(),
        "app",
        opts(false),
    )
    .unwrap();
}

/// Review #7: `--replace` never overwrites a same-named credential of
/// another provider.
#[test]
fn replace_refuses_a_same_named_credential_of_another_provider() {
    let (a, mut b, _c, cred) = trio();
    let other =
        b.v.add_credential(AddCredential {
            project: b.app.clone(),
            provider: "anthropic".into(),
            name: "openai_api_key".into(),
            environment: Environment::Development,
            value: SecretString::from("sk-test-FAKE-anthropic-0001"),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap()
        .0
        .id;
    a.v.mesh_credential_share(&master_pw(), &cred, devices(&[&b]))
        .unwrap();
    sync(&a, &b);
    let share = incoming(&b)[0].share_id.to_hex();
    let err =
        b.v.mesh_credential_import(&master_pw(), &share, "app", opts(true))
            .unwrap_err();
    assert!(err.to_string().contains("provider"), "{err}");
    assert_eq!(
        b.v.reveal_credential(&other, &master_pw())
            .unwrap()
            .expose(),
        "sk-test-FAKE-anthropic-0001"
    );
    assert_eq!(count(&b.v, "SELECT COUNT(*) FROM mesh_share_imports"), 0);
}

/// Review #8: the audit row commits with the share items, or neither does.
#[test]
fn a_share_whose_audit_row_fails_mints_nothing() {
    let (a, _b, _c, cred) = trio();
    // A schema trigger (the store writes on its own connection) refuses the
    // share's audit row.
    a.v.connection()
        .execute_batch(
            "CREATE TRIGGER refuse_share_audit BEFORE INSERT ON audit_events
             WHEN NEW.event = 'mesh_credential_shared'
             BEGIN SELECT RAISE(ABORT, 'refused by the test'); END;",
        )
        .unwrap();
    let err =
        a.v.mesh_credential_share(&master_pw(), &cred, Recipients::AllCurrent)
            .unwrap_err();
    assert_err_clean(&err);
    assert_eq!(share_items(&a.v), 0);
    assert_eq!(count(&a.v, "SELECT COUNT(*) FROM mesh_share_outgoing"), 0);
}
