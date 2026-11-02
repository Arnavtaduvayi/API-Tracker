//! The desktop's shared projects, cross-device usage and spend caps end to
//! end (Increment 10's manual run, without the window): the functions the
//! `mesh_project_cmds.rs` commands call, on two real data directories.
//!
//! "app" is the desktop: its node runs in-process (`NodeSupervisor`,
//! `sync_with_settings`) on 127.0.0.1:0. "cli" is a second data directory
//! driven the way `tethra mesh …` drives it: it pairs with the app's node,
//! binds the project the app shared, records gateway usage (seeded the way
//! the smoke test seeds it) and exchanges with the app's node. No discovery,
//! no LAN address, fake values only. The gateway's 403 over a cap is covered
//! by `crates/gateway/tests/cap_enforcement.rs`.

mod common;

use api_tracker_core::mesh::caps;
use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::kinds::Day;
use api_tracker_core::mesh::node_settings::NodeSettings;
use api_tracker_core::mesh::projects;
use api_tracker_core::mesh::usage::{UsageFilter, UsageReport};
use api_tracker_core::mesh::{DeviceId, MeshProjectId};
use api_tracker_core::vault::{NewProject, UnlockedVault};
use api_tracker_mesh::instance;
use api_tracker_mesh::node::GatewaySocket;
use api_tracker_mesh::replicate::replicate_known_peers;
use api_tracker_mesh::runtime::StopReason;
use api_tracker_mesh::supervisor::{sync_with_settings, NodeSupervisor, StartOutcome};
use common::{device_id, genesis, master, vault, wait_for, Dev};
use rusqlite::params;

const USD: u64 = 1_000_000;
/// The CLI device's priced spend today: $0.42.
const SPENT: u64 = 420_000;

fn local_project(dev: &mut Dev, name: &str) -> String {
    dev.vault
        .create_project(NewProject {
            name: name.to_owned(),
            ..Default::default()
        })
        .unwrap()
        .id
}

/// `tethra mesh replicate --peer <the app's node>` on the CLI device:
/// publish, reconcile, one exchange.
fn replicate(cli: &Dev, addr: &str) {
    let r = replicate_known_peers(&cli.vault, &cli.paths.data_dir, Some(addr.to_owned())).unwrap();
    assert!(r.notes.is_empty(), "{:?}", r.notes);
    assert_eq!(r.exchanges.len(), 1);
    assert!(r.exchanges[0].error.is_none(), "{:?}", r.exchanges[0]);
}

/// Gateway daily rows for `local` today, as the gateway's writer leaves
/// them: priced traffic, and traffic it could not price or whose usage it
/// could not extract (the mechanism `scripts/smoke.sh` uses).
fn seed_gateway_usage(dev: &Dev, local: &str) {
    let day = Day::from_unix_ms(SystemClock.now_ms()).to_string();
    // (model, requests, with usage, unpriced, unextracted, cost)
    for (model, reqs, with_usage, unpriced, unextracted, cost) in [
        (
            "fake-priced-model",
            5_i64,
            5_i64,
            0_i64,
            0_i64,
            SPENT as i64,
        ),
        ("fake-unpriced-model", 4, 3, 3, 1, 0),
    ] {
        dev.vault
            .connection()
            .execute(
                "INSERT INTO gateway_usage_daily
                    (day, provider_id, project_id, model, request_count, usage_event_count,
                     input_tokens, output_tokens, cached_input_tokens, estimated_cost_micros,
                     updated_at, unpriced_requests, unextracted_requests, split_known)
                 VALUES (?1, 'openai', ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, 'x', ?9, ?10, 1)",
                params![
                    day,
                    local,
                    model,
                    reqs,
                    with_usage,
                    reqs * 100,
                    reqs * 10,
                    cost,
                    unpriced,
                    unextracted
                ],
            )
            .unwrap();
    }
}

/// `mesh_usage_report` without `publish` (the polled read): the filter's
/// project resolved by core, then the report.
fn usage_of(v: &UnlockedVault, project: &MeshProjectId) -> UsageReport {
    let filter = UsageFilter {
        project: Some(projects::resolve(&v.mesh_open_store().unwrap(), &project.to_hex()).unwrap()),
        ..Default::default()
    };
    v.mesh_usage(&filter).unwrap()
}

/// `mesh_caps_list` without `reconcile` (the polled read).
fn caps_of(v: &UnlockedVault) -> caps::CapReport {
    caps::report(&v.mesh_open_store().unwrap(), None, None).unwrap()
}

fn rows(v: &UnlockedVault, table: &str) -> i64 {
    v.connection()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

/// `id`'s row in the cap's current month.
fn cap_device(r: &caps::CapReport, id: DeviceId) -> Option<caps::view::CapDeviceRow> {
    r.caps
        .first()?
        .months
        .first()?
        .devices
        .iter()
        .find(|d| d.device_id == id)
        .cloned()
}

#[test]
fn a_project_shared_in_the_app_shows_the_cli_devices_usage_and_its_cap() {
    // The desktop app: a mesh, a local project, the node in-process on
    // loopback ("Run mesh while Tethra is open"; no reauthentication).
    let mut app = genesis("app");
    let app_dir = app.paths.data_dir.clone();
    let web = local_project(&mut app, "web");
    app.vault
        .mesh_node_settings_set(
            None,
            &NodeSettings {
                run_while_open: true,
                listen: vec!["127.0.0.1:0".into()],
                all_interfaces: false,
                discover: false,
            },
        )
        .unwrap();
    let sup = NodeSupervisor::new();
    assert_eq!(
        sync_with_settings(&sup, &app.vault, &app_dir, None).unwrap(),
        StartOutcome::Started
    );
    let addr = sup.state().running.unwrap().advertised[0].clone();
    assert!(addr.starts_with("127.0.0.1:"), "{addr}");
    let app_id = device_id(&app);

    // The CLI device pairs with the app's node through an invite naming the
    // address it publishes (`tethra mesh join`).
    let mut cli = vault();
    let site = local_project(&mut cli, "site");
    let inv = app.vault.mesh_invite_create(&master(), None).unwrap();
    let text =
        api_tracker_core::mesh::invite::format_invite(&inv.token, std::slice::from_ref(&addr))
            .unwrap();
    let joined = common::join(&cli, &text, "cli").unwrap();
    assert!(joined.exchange.aborted.is_none(), "{:?}", joined.exchange);
    let cli_id = device_id(&cli);

    // `mesh_project_share` in the app.
    let (mesh_id, name) = app.vault.mesh_project_share(&web).unwrap();
    assert_eq!(name, "web");
    let mine = app.vault.mesh_projects().unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].bound_local_project.as_deref(), Some(web.as_str()));

    // The CLI device hears of it at its next exchange, and it stays unbound
    // there until bound explicitly (never automatic, MESH-SI-13).
    replicate(&cli, &addr);
    let theirs = cli.vault.mesh_projects().unwrap();
    let row = theirs
        .iter()
        .find(|r| r.mesh_project_id == mesh_id)
        .expect("the shared project reached the CLI device");
    assert_eq!(row.name, "web");
    assert!(row.bound_local_project.is_none());
    assert_eq!(
        cli.vault
            .mesh_project_bind(&mesh_id.to_hex(), &site)
            .unwrap(),
        mesh_id
    );

    // The CLI device's gateway records traffic for its bound project; it
    // publishes and exchanges with the app's node.
    seed_gateway_usage(&cli, &site);
    replicate(&cli, &addr);

    // The app's usage card: the CLI device's figures, labelled per device,
    // as of the exchange, unpriced and unextracted counted apart from the
    // estimate; the app itself is "no data", not zero.
    wait_for(
        5,
        || {
            usage_of(&app.vault, &mesh_id).projects[0]
                .devices
                .iter()
                .any(|d| d.device_id == cli_id && d.as_of.is_some())
        },
        "the CLI device's usage on the app",
    );
    let report = usage_of(&app.vault, &mesh_id);
    assert_eq!(report.projects.len(), 1);
    let p = &report.projects[0];
    assert_eq!((p.mesh_project_id, p.name.as_str()), (mesh_id, "web"));
    assert_eq!(p.devices.len(), 1);
    let d = &p.devices[0];
    assert_eq!(d.device_name.as_deref(), Some("cli"));
    assert!(!d.is_self && !d.stale && !d.removed);
    let t = &d.totals;
    assert_eq!(
        (
            t.requests,
            t.priced_requests,
            t.unpriced_requests,
            t.unextracted_requests
        ),
        (9, 5, 3, 1)
    );
    assert_eq!((t.input_tokens, t.output_tokens), (900, 90));
    assert_eq!(t.estimated_cost_micros, SPENT, "priced requests only");
    assert_eq!(d.split_unknown_requests, 0);
    assert_eq!(p.total.estimated_cost_micros, SPENT);
    assert_eq!(p.no_data_from, vec![(app_id, Some("app".to_owned()))]);
    assert_eq!(
        p.total_label,
        "estimated, gateway-observed, across 1 device(s); 0 stale; 1 with no data"
    );
    assert!(report
        .notes
        .iter()
        .any(|n| n.contains("never summed with provider-reported cost")));
    let listed = app.vault.mesh_projects().unwrap();
    assert_eq!(listed[0].publishing_devices, vec![cli_id]);

    // `mesh_cap_create` in the app: $100 a month, owned by the app, shared
    // equally with the CLI device (active: it exchanged).
    let probe = GatewaySocket::for_vault(&app.vault, &app_dir);
    let created = app
        .vault
        .mesh_cap_create(&mesh_id.to_hex(), 100 * USD, &probe)
        .unwrap();
    assert_eq!(created.mesh_project_id, mesh_id);
    assert_eq!(created.monthly_micros, 100 * USD);
    assert_eq!(created.distributed_micros, 50 * USD);
    let cap = created.cap_id;
    // `mesh_caps_list` (reconciling, then the polled read) shows it.
    for r in [
        app.vault.mesh_caps(None, None, &probe).unwrap(),
        caps_of(&app.vault),
    ] {
        assert_eq!(r.caps.len(), 1);
        let c = &r.caps[0];
        assert_eq!(c.cap_id, cap);
        assert!(c.owned_here && c.bound_here && !c.frozen && !c.enforced_here);
        assert_eq!(c.months[0].target, Some(100 * USD));
    }

    // After the next exchange the CLI device holds its rights, and its
    // spend this month counts against them.
    replicate(&cli, &addr);
    let cli_probe = GatewaySocket::for_vault(&cli.vault, &cli.paths.data_dir);
    let theirs = cli.vault.mesh_caps(None, None, &cli_probe).unwrap();
    assert_eq!(theirs.caps.len(), 1);
    let c = &theirs.caps[0];
    assert!(!c.owned_here && c.bound_here);
    let own = cap_device(&theirs, cli_id).unwrap();
    assert!(own.is_self);
    assert_eq!(own.received, u128::from(50 * USD));
    assert_eq!(own.used, u128::from(SPENT), "published by the reconciler");
    assert_eq!(c.months[0].local_avail, Some(i128::from(50 * USD - SPENT)));

    // Polled reads on the CLI device write nothing (no node runs there).
    let before = (
        rows(&cli.vault, "mesh_items"),
        rows(&cli.vault, "audit_events"),
    );
    let _ = cli.vault.mesh_projects().unwrap();
    let _ = usage_of(&cli.vault, &mesh_id);
    let _ = caps_of(&cli.vault);
    assert_eq!(
        (
            rows(&cli.vault, "mesh_items"),
            rows(&cli.vault, "audit_events")
        ),
        before
    );

    // Once it exchanged again, the app shows the CLI device's spend.
    replicate(&cli, &addr);
    wait_for(
        5,
        || cap_device(&caps_of(&app.vault), cli_id).is_some_and(|d| d.used == u128::from(SPENT)),
        "the CLI device's cap spend on the app",
    );
    let r = caps_of(&app.vault);
    let m = &r.caps[0].months[0];
    let theirs_on_app = cap_device(&r, cli_id).unwrap();
    assert!(!theirs_on_app.is_self && !theirs_on_app.stale);
    assert!(theirs_on_app.as_of.is_some());
    assert_eq!(theirs_on_app.received, u128::from(50 * USD));
    assert_eq!(m.total_used, u128::from(SPENT));
    assert_eq!(m.used_pct, Some(0));
    assert!(
        m.total_label
            .starts_with("estimated, gateway-observed, across 2 device(s)"),
        "{}",
        m.total_label
    );

    // `mesh_cap_enforce` on the CLI device, reauthenticated: on there only.
    let changed = cli
        .vault
        .mesh_cap_enforce(&master(), Some(&cap.to_hex()), true)
        .unwrap();
    assert_eq!(changed, vec![cap]);
    assert!(caps_of(&cli.vault).caps[0].enforced_here);
    replicate(&cli, &addr);
    assert!(
        !caps_of(&app.vault).caps[0].enforced_here,
        "the switch is local to the device that set it"
    );

    // Lock: the app's node stops, drops its keys and frees the data
    // directory.
    sup.lock();
    wait_for(
        5,
        || instance::running_pid(&app_dir).is_none(),
        "the node to release the data directory",
    );
    wait_for(5, || sup.state().last_stop.is_some(), "the node's stop");
    let stop = sup.state().last_stop.unwrap();
    assert_eq!(stop.reason, StopReason::Locked);
    assert!(stop.keys_dropped);
    assert!(instance::status(&app_dir).is_none());
}
