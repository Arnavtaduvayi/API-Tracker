//! Shared projects, the usage publisher and cross-device usage views
//! (Increment 06). Two or three real vaults in temp directories, paired with
//! core's own pairing steps and replicated through the sans-IO session (the
//! network path is `api-tracker-mesh`'s). Gateway rows are written directly
//! here; `crates/gateway/tests/mesh_publish_e2e.rs` drives the real writer.

mod common;

use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::dot::{CapId, MeshProjectId};
use api_tracker_core::mesh::kinds::{CapDef, Day, Month, UsageKey, UsageTotals};
use api_tracker_core::mesh::membership::{self, ExchangeRecord, PendingIdentity};
use api_tracker_core::mesh::proto::{Action, Frame, Limits, Session};
use api_tracker_core::mesh::publish::{self, UNKNOWN_MODEL};
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::{Draft, HlcPolicy, MeshStore};
use api_tracker_core::mesh::usage::{usage_report, UsageFilter};
use api_tracker_core::mesh::{projects, DeviceId};
use api_tracker_core::vault::{UnlockedVault, VaultPaths};
use common::{add_project, master_pw, new_vault};
use rusqlite::params;
use tempfile::TempDir;

struct Dev {
    _dir: TempDir,
    paths: VaultPaths,
    v: UnlockedVault,
    /// A local project id ("app").
    app: String,
}

fn dev(name: &str) -> Dev {
    let (dir, paths, mut v) = new_vault();
    let app = add_project(&mut v, "app").id;
    let _ = name;
    Dev {
        _dir: dir,
        paths,
        v,
        app,
    }
}

fn id(d: &Dev) -> DeviceId {
    d.v.mesh_status().unwrap().detail.unwrap().device_id
}

fn store(d: &Dev) -> SqliteStore {
    d.v.mesh_open_store().unwrap()
}

fn now() -> u64 {
    SystemClock.now_ms()
}

fn today() -> Day {
    Day::from_unix_ms(now())
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

/// Exchange two devices and log it (as the network layer does), so views
/// have an "as of".
fn sync(a: &Dev, b: &Dev) {
    let (mut sa, mut sb) = (store(a), store(b));
    exchange(&mut sa, &mut sb);
    for (s, peer) in [(&sa, id(b)), (&sb, id(a))] {
        membership::log_exchange(
            s.connection(),
            &ExchangeRecord {
                peer_device: Some(peer),
                direction: "outbound",
                items_in: 0,
                items_out: 0,
                result: "ok",
                error: None,
            },
        )
        .unwrap();
    }
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

fn pair() -> (Dev, Dev) {
    let a = dev("a");
    a.v.mesh_init("dev-a").unwrap();
    let b = dev("b");
    join(&a, &b, "dev-b");
    (a, b)
}

/// A gateway daily row, as the writer would leave it (split known).
#[allow(clippy::too_many_arguments)]
fn seed(
    d: &Dev,
    project: &str,
    day: &Day,
    model: &str,
    reqs: i64,
    unpriced: i64,
    unextracted: i64,
    cost: i64,
) {
    d.v.connection()
        .execute(
            "INSERT INTO gateway_usage_daily
                (day, provider_id, project_id, model, request_count, usage_event_count,
                 input_tokens, output_tokens, cached_input_tokens, estimated_cost_micros,
                 updated_at, unpriced_requests, unextracted_requests, split_known)
             VALUES (?1, 'openai', ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, 'x', ?9, ?10, 1)
             ON CONFLICT(day, provider_id, project_id, model) DO UPDATE SET
                request_count = request_count + excluded.request_count,
                usage_event_count = usage_event_count + excluded.usage_event_count,
                input_tokens = input_tokens + excluded.input_tokens,
                output_tokens = output_tokens + excluded.output_tokens,
                estimated_cost_micros = estimated_cost_micros + excluded.estimated_cost_micros,
                unpriced_requests = unpriced_requests + excluded.unpriced_requests,
                unextracted_requests = unextracted_requests + excluded.unextracted_requests",
            params![
                day.to_string(),
                project,
                model,
                reqs,
                reqs - unextracted,
                reqs * 100,
                reqs * 10,
                cost,
                unpriced,
                unextracted
            ],
        )
        .unwrap();
}

fn key(p: MeshProjectId, day: Day, model: &str) -> UsageKey {
    UsageKey {
        project: p,
        day,
        provider: "openai".into(),
        model: model.into(),
    }
}

fn counter(s: &SqliteStore, owner: DeviceId, k: &UsageKey) -> Option<(u32, UsageTotals)> {
    s.state()
        .usage
        .get(k, &owner)
        .map(|e| (e.value.epoch, e.value.totals))
}

#[test]
fn usage_on_a_reaches_b_labelled_per_device_with_freshness() {
    let (a, b) = pair();
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    seed(&a, &a.app, &today(), "gpt-x", 10, 2, 1, 7_000);
    let r = a.v.mesh_publish().unwrap();
    assert_eq!(r.minted, 1);
    sync(&a, &b);
    // Sharing on A created no binding on B (MESH-SI-13).
    assert!(projects::bindings(b.v.connection()).unwrap().is_empty());
    b.v.mesh_project_bind(&p.to_hex(), &b.app).unwrap();
    let report = b.v.mesh_usage(&UsageFilter::default()).unwrap();
    let pu = &report.projects[0];
    assert_eq!(pu.mesh_project_id, p);
    let from_a = pu.devices.iter().find(|d| d.device_id == id(&a)).unwrap();
    assert_eq!(from_a.device_name.as_deref(), Some("dev-a"));
    assert!(!from_a.is_self && !from_a.stale && !from_a.removed);
    assert!(from_a.as_of.is_some());
    let t = from_a.totals;
    assert_eq!(
        (
            t.requests,
            t.priced_requests,
            t.unpriced_requests,
            t.unextracted_requests
        ),
        (10, 7, 2, 1)
    );
    assert_eq!(t.estimated_cost_micros, 7_000);
    // B has published nothing for P: unknown, not zero.
    assert_eq!(
        pu.no_data_from.iter().map(|(d, _)| *d).collect::<Vec<_>>(),
        vec![id(&b)]
    );
    assert!(pu
        .total_label
        .contains("estimated, gateway-observed, across 1 device(s)"));
    assert!(report
        .notes
        .iter()
        .any(|n| n.contains("never summed with provider-reported")));
}

#[test]
fn deltas_accumulate_and_a_second_run_with_no_traffic_mints_nothing() {
    let a = dev("a");
    a.v.mesh_init("dev-a").unwrap();
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    let d = today();
    seed(&a, &a.app, &d, "gpt-x", 3, 0, 0, 300);
    assert_eq!(a.v.mesh_publish().unwrap().minted, 1);
    seed(&a, &a.app, &d, "gpt-x", 4, 1, 0, 300);
    assert_eq!(a.v.mesh_publish().unwrap().minted, 1);
    let (epoch, t) = counter(&store(&a), id(&a), &key(p, d, "gpt-x")).unwrap();
    assert_eq!(
        (epoch, t.requests, t.unpriced_requests, t.priced_requests),
        (0, 7, 1, 6)
    );
    assert_eq!(t.estimated_cost_micros, 600);
    let seq = store(&a).vv().get(&id(&a));
    let r = a.v.mesh_publish().unwrap();
    assert_eq!((r.minted, r.epoch_bumps), (0, 0));
    assert_eq!(
        store(&a).vv().get(&id(&a)),
        seq,
        "idempotent: nothing minted"
    );
}

#[test]
fn rebinding_mid_day_moves_only_later_traffic() {
    let a = dev("a");
    a.v.mesh_init("dev-a").unwrap();
    let (m, _) = a.v.mesh_project_share(&a.app).unwrap();
    let d = today();
    seed(&a, &a.app, &d, "gpt-x", 5, 0, 0, 500);
    a.v.mesh_publish().unwrap();
    // Another device's project N; this device rebinds its "app" to it.
    let mut s = store(&a);
    let keys = a.v.mesh_keys().unwrap();
    let n = MeshProjectId::random();
    s.mint(
        keys.signing_key(),
        Draft::of(
            &api_tracker_core::mesh::kinds::ProjectMeta {
                project: n,
                name: "app-elsewhere".into(),
                archived: false,
                merged_into: None,
            },
            HlcPolicy::Now,
        ),
    )
    .unwrap();
    drop(s);
    assert!(a.v.mesh_project_unbind(&a.app).unwrap());
    a.v.mesh_project_bind(&n.to_hex(), &a.app).unwrap();
    seed(&a, &a.app, &d, "gpt-x", 2, 0, 0, 200);
    a.v.mesh_publish().unwrap();
    let s = store(&a);
    assert_eq!(
        counter(&s, id(&a), &key(m, d, "gpt-x")).unwrap().1.requests,
        5
    );
    assert_eq!(
        counter(&s, id(&a), &key(n, d, "gpt-x")).unwrap().1.requests,
        2
    );
}

#[test]
fn deleting_local_data_bumps_the_epoch_and_the_peer_sees_the_reduction() {
    let (a, b) = pair();
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    let d = today();
    seed(&a, &a.app, &d, "gpt-x", 9, 0, 0, 900);
    a.v.mesh_publish().unwrap();
    sync(&a, &b);
    assert_eq!(
        counter(&store(&b), id(&a), &key(p, d, "gpt-x"))
            .unwrap()
            .1
            .requests,
        9
    );
    // The deletion tool for a project's gateway data.
    api_tracker_core::runtime::store::delete_project_data(a.v.connection(), &a.app).unwrap();
    let r = a.v.mesh_publish().unwrap();
    assert_eq!((r.minted, r.epoch_bumps), (1, 1));
    sync(&a, &b);
    let (epoch, t) = counter(&store(&b), id(&a), &key(p, d, "gpt-x")).unwrap();
    assert_eq!((epoch, t), (1, UsageTotals::default()));
}

#[test]
fn the_retention_sweep_bumps_the_epoch_and_old_counters_are_collected() {
    let (a, b) = pair();
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    let recent = Day::from_unix_ms(now() - 5 * 86_400_000);
    seed(&a, &a.app, &recent, "gpt-x", 4, 0, 0, 40);
    a.v.mesh_publish().unwrap();
    // The gateway's retention sweep removes the row (as `sweep_gateway_tables`).
    a.v.connection()
        .execute(
            "DELETE FROM gateway_usage_daily WHERE day <= ?1",
            [recent.to_string()],
        )
        .unwrap();
    assert_eq!(a.v.mesh_publish().unwrap().epoch_bumps, 1);
    sync(&a, &b);
    assert_eq!(
        counter(&store(&b), id(&a), &key(p, recent, "gpt-x"))
            .unwrap()
            .0,
        1
    );
    // A horizon of one day: the counter falls out and is collected on B
    // when B's publisher runs.
    a.v.mesh_setting_set("retention.usage_days", "1").unwrap();
    sync(&a, &b);
    let r = b.v.mesh_publish().unwrap();
    assert_eq!(r.retention_days, 1);
    assert_eq!(r.collected, 1);
    assert!(counter(&store(&b), id(&a), &key(p, recent, "gpt-x")).is_none());
    // And a peer that still sends it has it dropped at ingest: not rejected.
    let mut sb = b.v.mesh_open_store().unwrap();
    publish::apply_retention(&mut sb, now()).unwrap();
    assert_eq!(sb.stats().rejected_items, 0);
}

#[test]
fn rows_without_a_model_publish_as_not_reported_and_unattributed_rows_never() {
    let a = dev("a");
    a.v.mesh_init("dev-a").unwrap();
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    let d = today();
    seed(&a, &a.app, &d, "", 2, 2, 0, 0);
    seed(&a, "", &d, "gpt-x", 50, 0, 0, 5_000);
    let r = a.v.mesh_publish().unwrap();
    assert_eq!(r.minted, 1);
    let (_, t) = counter(&store(&a), id(&a), &key(p, d, UNKNOWN_MODEL)).unwrap();
    assert_eq!(
        (t.requests, t.unpriced_requests, t.estimated_cost_micros),
        (2, 2, 0)
    );
}

#[test]
fn rows_from_before_the_split_publish_an_honest_unknown_remainder() {
    let a = dev("a");
    a.v.mesh_init("dev-a").unwrap();
    a.v.mesh_project_share(&a.app).unwrap();
    let old = Day::from_unix_ms(now() - 3 * 86_400_000);
    // Written before migration v23: 6 requests, 4 with usage.
    a.v.connection()
        .execute(
            "INSERT INTO gateway_usage_daily (day, provider_id, project_id, model,
                 request_count, usage_event_count, estimated_cost_micros, updated_at)
             VALUES (?1, 'openai', ?2, 'gpt-x', 6, 4, 100, 'x')",
            params![old.to_string(), a.app],
        )
        .unwrap();
    seed(&a, &a.app, &today(), "gpt-x", 3, 0, 0, 30);
    a.v.mesh_publish().unwrap();
    let report = a.v.mesh_usage(&UsageFilter::default()).unwrap();
    let d = &report.projects[0].devices[0];
    if old.month() == today().month() {
        assert_eq!(d.split_unknown_requests, 4);
        assert_eq!(d.totals.unextracted_requests, 2);
        assert_eq!(d.split_known_since, Some(old.next()));
    }
    let r =
        a.v.mesh_usage(&UsageFilter {
            day: Some(old),
            ..Default::default()
        })
        .unwrap();
    let d = &r.projects[0].devices[0];
    assert_eq!((d.totals.requests, d.split_unknown_requests), (6, 4));
}

#[test]
fn the_hourly_budget_publishes_the_oldest_days_first_and_defers_the_rest() {
    let a = dev("a");
    a.v.mesh_init("dev-a").unwrap();
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    let days: Vec<Day> = (0..5)
        .map(|i| Day::from_unix_ms(now() - (5 - i) * 86_400_000))
        .collect();
    for d in &days {
        seed(&a, &a.app, d, "gpt-x", 1, 0, 0, 1);
    }
    let keys = a.v.mesh_keys().unwrap();
    let mut s = store(&a);
    let r = publish::publish_with_budget(&mut s, keys.signing_key(), now(), 3).unwrap();
    assert_eq!((r.minted, r.deferred), (3, 2));
    for (i, d) in days.iter().enumerate() {
        assert_eq!(
            counter(&s, id(&a), &key(p, *d, "gpt-x")).is_some(),
            i < 3,
            "{d}"
        );
    }
    // The same hour: the budget is spent.
    let r = publish::publish_with_budget(&mut s, keys.signing_key(), now(), 3).unwrap();
    assert_eq!((r.minted, r.deferred), (0, 2));
    // The next hour: the rest goes out.
    let later = now() + 3_600_000;
    let r = publish::publish_with_budget(&mut s, keys.signing_key(), later, 3).unwrap();
    assert_eq!((r.minted, r.deferred), (2, 0));
}

#[test]
fn binding_is_never_automatic_cascades_on_delete_and_is_refused_twice() {
    let (mut a, b) = pair();
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    sync(&a, &b);
    // B has a local project with the same name: still not bound.
    assert!(projects::bindings(b.v.connection()).unwrap().is_empty());
    let err = a.v.mesh_project_share(&a.app).unwrap_err();
    assert!(err.to_string().contains("already bound"), "{err}");
    let other = add_project(&mut a.v, "other").id;
    let err = a.v.mesh_project_bind(&p.to_hex(), &a.app).unwrap_err();
    assert!(err.to_string().contains("already bound"), "{err}");
    a.v.mesh_project_bind(&p.to_hex(), &other).unwrap();
    assert_eq!(projects::bindings(a.v.connection()).unwrap().len(), 2);
    // Deleting the local project (foreign keys on) unbinds it.
    a.v.connection()
        .execute("DELETE FROM projects WHERE id = ?1", [&other])
        .unwrap();
    assert_eq!(projects::bindings(a.v.connection()).unwrap().len(), 1);
    // Archived projects cannot be bound.
    a.v.mesh_project_archive(&p.to_hex()).unwrap();
    sync(&a, &b);
    let err = b.v.mesh_project_bind(&p.to_hex(), &b.app).unwrap_err();
    assert!(err.to_string().contains("archived"), "{err}");
}

#[test]
fn merge_folds_counters_into_the_root_and_is_refused_when_both_have_caps() {
    let (mut a, b) = pair();
    let (x, _) = a.v.mesh_project_share(&a.app).unwrap();
    let second = add_project(&mut a.v, "app-copy").id;
    let (y, _) = a.v.mesh_project_share(&second).unwrap();
    let d = today();
    seed(&a, &a.app, &d, "gpt-x", 2, 0, 0, 20);
    seed(&a, &second, &d, "gpt-x", 3, 0, 0, 30);
    a.v.mesh_publish().unwrap();
    let (root, merged) = a.v.mesh_project_merge(&x.to_hex(), &y.to_hex()).unwrap();
    assert_eq!(root, x.min(y));
    assert_eq!(merged, x.max(y));
    sync(&a, &b);
    let report = b.v.mesh_usage(&UsageFilter::default()).unwrap();
    assert_eq!(report.projects.len(), 1);
    assert_eq!(report.projects[0].mesh_project_id, root);
    assert_eq!(report.projects[0].merged, vec![merged]);
    assert_eq!(report.projects[0].devices[0].totals.requests, 5);
    // Two projects that both have caps cannot merge.
    let third = add_project(&mut a.v, "third").id;
    let fourth = add_project(&mut a.v, "fourth").id;
    let (z, _) = a.v.mesh_project_share(&third).unwrap();
    let (w, _) = a.v.mesh_project_share(&fourth).unwrap();
    let keys = a.v.mesh_keys().unwrap();
    let mut s = store(&a);
    for proj in [z, w] {
        let hlc = s.hlc_last();
        s.mint(
            keys.signing_key(),
            Draft::of(
                &CapDef {
                    cap: CapId::random(),
                    mesh_project_id: proj,
                    owner_device: id(&a),
                    created_hlc: hlc,
                },
                HlcPolicy::Now,
            ),
        )
        .unwrap();
    }
    drop(s);
    let err =
        a.v.mesh_project_merge(&z.to_hex(), &w.to_hex())
            .unwrap_err();
    assert!(err.to_string().contains("spend caps"), "{err}");
}

#[test]
fn views_label_stale_and_removed_devices_and_devices_with_no_data() {
    let (a, b) = pair();
    let c = dev("c");
    join(&a, &c, "dev-c");
    let (p, _) = a.v.mesh_project_share(&a.app).unwrap();
    sync(&a, &b);
    b.v.mesh_project_bind(&p.to_hex(), &b.app).unwrap();
    seed(&b, &b.app, &today(), "gpt-x", 4, 0, 0, 40);
    b.v.mesh_publish().unwrap();
    sync(&a, &b);
    let sa = store(&a);
    // Now: B fresh. A day later (injected time): B stale.
    let f = UsageFilter::default();
    let fresh = usage_report(&sa, &f, now()).unwrap();
    let bd = fresh.projects[0]
        .devices
        .iter()
        .find(|d| d.device_id == id(&b))
        .unwrap();
    assert!(!bd.stale);
    let later = usage_report(&sa, &f, now() + 25 * 3_600_000).unwrap();
    let bd = later.projects[0]
        .devices
        .iter()
        .find(|d| d.device_id == id(&b))
        .unwrap();
    assert!(bd.stale, "{bd:?}");
    // A and C have no data for P: listed, unknown.
    let none: Vec<DeviceId> = fresh.projects[0]
        .no_data_from
        .iter()
        .map(|(d, _)| *d)
        .collect();
    assert!(none.contains(&id(&a)) && none.contains(&id(&c)), "{none:?}");
    drop(sa);
    // B is removed: its counters up to the cutoff still count, labelled.
    a.v.mesh_device_remove(&master_pw(), &id(&b).to_hex())
        .unwrap();
    let r = a.v.mesh_usage(&f).unwrap();
    let bd = r.projects[0]
        .devices
        .iter()
        .find(|d| d.device_id == id(&b))
        .unwrap();
    assert!(bd.removed);
    assert_eq!(bd.totals.requests, 4);
    assert!(!r.projects[0].no_data_from.iter().any(|(d, _)| *d == id(&b)));
    let _ = (&c.paths, Month::new(2026, 10));
}

#[test]
fn published_items_carry_no_path_endpoint_host_request_or_credential() {
    let a = dev("a");
    a.v.mesh_init("dev-a").unwrap();
    a.v.mesh_project_share(&a.app).unwrap();
    seed(&a, &a.app, &today(), "gpt-x", 1, 0, 0, 1);
    a.v.mesh_publish().unwrap();
    a.v.mesh_setting_set("retention.usage_days", "30").unwrap();
    let allowed: &[(&str, &[&str])] = &[
        ("usage.counter", &["epoch", "totals"]),
        ("project.meta", &["archived", "merged_into", "name"]),
        ("mesh.setting", &["value"]),
    ];
    let totals_fields = [
        "requests",
        "priced_requests",
        "unpriced_requests",
        "unextracted_requests",
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "estimated_cost_micros",
    ];
    let mut seen = 0;
    for item in store(&a).all_items().unwrap() {
        let body = item.decode_unverified().unwrap();
        let Some((_, keys)) = allowed.iter().find(|(k, _)| *k == body.kind) else {
            continue;
        };
        seen += 1;
        let obj = body.payload.as_object().unwrap();
        for k in obj.keys() {
            assert!(
                keys.contains(&k.as_str()),
                "{}: unexpected payload key {k}",
                body.kind
            );
        }
        if body.kind == "usage.counter" {
            for k in obj["totals"].as_object().unwrap().keys() {
                assert!(totals_fields.contains(&k.as_str()), "totals key {k}");
            }
            // project/day/provider/model, nothing else in the key.
            assert_eq!(body.key.splitn(4, '/').count(), 4);
        }
        let text = serde_json::to_string(&body.payload).unwrap() + &body.key;
        for banned in [
            "/v1/",
            "http",
            "api.openai.com",
            "request_id",
            "credential",
            "sk-",
        ] {
            assert!(!text.contains(banned), "{banned} in {text}");
        }
    }
    assert!(seen >= 3, "{seen}");
}
