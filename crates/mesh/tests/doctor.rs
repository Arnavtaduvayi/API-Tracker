//! `tethra mesh doctor` (Increment 05): every check's failure is detectable,
//! and `--rebuild` and `--repair` do what they say. Corruption is made by
//! writing to the test vault's database and marker directly.

mod common;

use api_tracker_core::mesh::clock::SystemClock;
use api_tracker_core::mesh::doctor::{Finding, Severity};
use api_tracker_core::mesh::dot::MarkerNonce;
use api_tracker_core::mesh::marker::{self, MarkerContents};
use api_tracker_mesh::doctor::{run, DoctorOptions, DoctorReport};
use api_tracker_mesh::runtime::Never;
use common::*;
use rusqlite::Connection;
use std::sync::Arc;

fn doctor(dev: &Dev, rebuild: bool, repair: bool) -> DoctorReport {
    run(
        &dev.vault,
        &dev.paths.data_dir,
        Arc::new(SystemClock),
        DoctorOptions { rebuild, repair },
    )
    .unwrap()
}

fn finding<'a>(r: &'a DoctorReport, check: &str) -> &'a Finding {
    r.findings
        .iter()
        .find(|f| f.check == check)
        .unwrap_or_else(|| panic!("no {check} finding in {:#?}", r.findings))
}

fn db(dev: &Dev) -> Connection {
    api_tracker_core::db::open(&dev.paths.db_path()).unwrap()
}

fn assert_fixes_are_given(r: &DoctorReport) {
    for f in &r.findings {
        if f.severity != Severity::Ok {
            assert!(f.fix.as_deref().is_some_and(|x| x.len() > 10), "{f:?}");
        }
    }
}

#[test]
fn a_healthy_device_has_no_problem_and_a_device_outside_a_mesh_has_little_to_check() {
    let outside = vault();
    let r = doctor(&outside, false, false);
    assert!(!r.initialized);
    assert!(r.worst() <= Severity::Info);

    let (a, _server, b) = pair_of();
    let r = doctor(&b, false, false);
    assert!(r.initialized);
    for check in [
        "schema",
        "keys",
        "sealing_key",
        "items",
        "marker",
        "fork",
        "dot_log",
        "views",
        "clock_skew",
        "rejected",
        "rollback",
        "repair",
        "digests",
    ] {
        assert_eq!(finding(&r, check).severity, Severity::Ok, "{check}");
    }
    // No node runs: said, with how to fix it. Joining made the inviter's
    // address a peer.
    assert_eq!(finding(&r, "node").severity, Severity::Info);
    assert_eq!(finding(&r, "peers").severity, Severity::Ok);
    assert_fixes_are_given(&r);
    // The genesis knows no address to dial.
    let r = doctor(&a, false, false);
    assert_eq!(finding(&r, "peers").severity, Severity::Warning);
    assert_fixes_are_given(&r);
    // Nothing in a report is key material.
    let json = serde_json::to_string(&r).unwrap();
    let keys = b.vault.mesh_keys().unwrap();
    for secret in [
        keys.expose_access_key().to_vec(),
        keys.expose_noise_secret().to_vec(),
    ] {
        let hex: String = secret.iter().map(|x| format!("{x:02x}")).collect();
        assert!(!json.contains(&hex));
    }
    drop(a);
}

#[test]
fn a_corrupt_item_row_is_found_and_rebuild_restores_the_store() {
    let (_a, _server, b) = pair_of();
    // An index column that disagrees with the bytes (the derived "view" of
    // a row).
    db(&b)
        .execute(
            "UPDATE mesh_items SET kind = 'project.meta' WHERE kind = 'device.info'
             AND rowid = (SELECT MIN(rowid) FROM mesh_items WHERE kind = 'device.info')",
            [],
        )
        .unwrap();
    let r = doctor(&b, false, false);
    let f = finding(&r, "items");
    assert_eq!(f.severity, Severity::Problem);
    assert!(
        f.summary.contains("1 row(s) whose columns disagree"),
        "{f:?}"
    );
    assert!(f.fix.as_deref().unwrap().contains("--rebuild"));
    let r = doctor(&b, true, false);
    assert_eq!(r.rebuild.as_ref().unwrap().rows_rewritten, 1);
    assert_eq!(r.rebuild.as_ref().unwrap().rows_removed, 0);
    assert_eq!(finding(&r, "items").severity, Severity::Ok);
    assert_eq!(finding(&r, "views").severity, Severity::Ok);

    // Bytes that no longer parse: the store cannot even load.
    db(&b)
        .execute(
            "UPDATE mesh_items SET bytes = x'00' WHERE kind = 'device.info'
             AND rowid = (SELECT MIN(rowid) FROM mesh_items WHERE kind = 'device.info')",
            [],
        )
        .unwrap();
    assert!(b.vault.mesh_open_store().is_err());
    let r = doctor(&b, false, false);
    assert_eq!(finding(&r, "items").severity, Severity::Problem);
    assert_eq!(finding(&r, "store").severity, Severity::Problem);
    assert_fixes_are_given(&r);
    let r = doctor(&b, true, false);
    assert_eq!(r.rebuild.as_ref().unwrap().rows_removed, 1);
    assert_eq!(finding(&r, "items").severity, Severity::Ok);
    assert_eq!(finding(&r, "dot_log").severity, Severity::Ok);
    b.vault.mesh_open_store().unwrap();
}

#[test]
fn a_marker_mismatch_is_found_and_the_node_refuses_to_start() {
    let a = genesis("dev-a");
    let me = device_id(&a);
    marker::write(
        &a.paths.data_dir,
        &MarkerContents::new(me, MarkerNonce::from_bytes([9; 16]), 64),
    )
    .unwrap();
    let r = doctor(&a, false, false);
    let f = finding(&r, "marker");
    assert_eq!(f.severity, Severity::Problem);
    assert!(f.fix.as_deref().unwrap().contains("mesh leave"));
    let err = api_tracker_mesh::MeshNode::open(&a.vault, Arc::new(SystemClock), test_limits())
        .err()
        .expect("a node on an untrusted identity");
    assert!(err.to_string().contains("cannot be trusted"), "{err}");
}

#[test]
fn a_repair_that_changes_state_is_reported_as_a_bug_signal() {
    let (a, server, b) = pair_of();
    b.vault.mesh_peer_add(&server.addr_string()).unwrap();
    // B loses one of A's items from storage while its VV still covers it,
    // so only repair can bring it back.
    let deleted = db(&b)
        .execute(
            "DELETE FROM mesh_items WHERE kind = 'device.info' AND origin = ?1",
            [device_id(&a).to_hex()],
        )
        .unwrap();
    assert_eq!(deleted, 1);
    assert_eq!(
        finding(&doctor(&b, false, false), "repair").severity,
        Severity::Ok
    );
    // No node runs on B: doctor runs the repair round itself.
    let r = doctor(&b, false, true);
    let summary = r.repair.as_ref().unwrap();
    assert!(!summary.via_node);
    assert_eq!(summary.exchanges, 1);
    assert!(summary.changed >= 1, "{summary:?}");
    assert_eq!(finding(&r, "repair_round").severity, Severity::Warning);
    // The item is back, and the next doctor flags the change.
    assert!(name_seen_by(&b, &a).is_some());
    let r = doctor(&b, false, false);
    let f = finding(&r, "repair");
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.summary.contains("changed stored state"), "{f:?}");
    drop(server);
}

#[test]
fn with_a_node_running_doctor_checks_its_listener_and_repairs_through_it() {
    let a = genesis("dev-a");
    let na = run_node(
        &a,
        node_config(60_000),
        Arc::new(SystemClock),
        Box::new(Never),
    );
    let b = vault();
    join_via(&a, &na.listen_addrs()[0].to_string(), &b, "dev-b");
    b.vault
        .mesh_peer_add(&na.listen_addrs()[0].to_string())
        .unwrap();
    let nb = run_node(
        &b,
        node_config(60_000),
        Arc::new(SystemClock),
        Box::new(Never),
    );
    let r = doctor(&b, false, true);
    assert_eq!(finding(&r, "node").severity, Severity::Ok);
    assert_eq!(finding(&r, "listener").severity, Severity::Ok);
    assert_eq!(finding(&r, "peers").severity, Severity::Ok);
    let summary = r.repair.as_ref().unwrap();
    assert!(summary.via_node);
    assert_eq!((summary.exchanges, summary.changed), (1, 0));
    assert_eq!(finding(&r, "repair_round").severity, Severity::Ok);
    for n in [na, nb] {
        n.stop();
        n.wait();
    }
}
