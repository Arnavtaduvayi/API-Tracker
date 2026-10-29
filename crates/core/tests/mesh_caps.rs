//! Spend caps (Increment 07): creating, minting in advance, distributing,
//! rebalancing, raising, overrides, lowering, reclaiming, freezing, `used`
//! publishing, the escrow fence and alerts. Real vaults in temp directories
//! with an injected clock, paired with core's own pairing steps and
//! replicated through the sans-IO session; rights requests travel as real
//! `Direct` frames inside it. The network path is `api-tracker-mesh`'s
//! (`apps/cli/tests/mesh_cli.rs` drives it with two real nodes).

mod common;

use api_tracker_core::alerts;
use api_tracker_core::mesh::caps::escrow::{self, EscrowState};
use api_tracker_core::mesh::caps::period;
use api_tracker_core::mesh::caps::policy;
use api_tracker_core::mesh::caps::view::{self, Ledger};
use api_tracker_core::mesh::caps::{self, AssumeNotRunning, AssumeRunning, GatewayProbe};
use api_tracker_core::mesh::clock::{Clock, ManualClock};
use api_tracker_core::mesh::dot::{CapId, MeshProjectId};
use api_tracker_core::mesh::identity;
use api_tracker_core::mesh::kinds::{Month, Recipient};
use api_tracker_core::mesh::membership::{self, PendingIdentity};
use api_tracker_core::mesh::proto::{Action, DirectMsg, Frame, Limits, Session};
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::{projects, DeviceId};
use api_tracker_core::vault::{UnlockedVault, VaultPaths};
use common::{add_project, master_pw, new_vault};
use rusqlite::params;
use std::sync::Arc;
use tempfile::TempDir;

const USD: u64 = 1_000_000;

/// 2027-03-10T12:00:00Z.
const MARCH_10: u64 = 1_804_680_000_000;

fn at(day: &str, hms: &str) -> u64 {
    let t = time::OffsetDateTime::parse(
        &format!("{day}T{hms}Z"),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    (t.unix_timestamp_nanos() / 1_000_000) as u64
}

fn month(s: &str) -> Month {
    Month::parse(s).unwrap()
}

struct Dev {
    _dir: TempDir,
    paths: VaultPaths,
    v: UnlockedVault,
    app: String,
    clock: Arc<ManualClock>,
}

fn dev(now: u64) -> Dev {
    let (dir, paths, mut v) = new_vault();
    let app = add_project(&mut v, "app").id;
    Dev {
        _dir: dir,
        paths,
        v,
        app,
        clock: Arc::new(ManualClock::new(now)),
    }
}

fn set_time(devs: &[&Dev], ms: u64) {
    for d in devs {
        d.clock.set(ms);
    }
}

fn store(d: &Dev) -> SqliteStore {
    identity::open_store(&d.paths.db_path(), &d.paths.data_dir, d.clock.clone())
        .unwrap()
        .unwrap()
}

fn id(d: &Dev) -> DeviceId {
    store(d).self_id()
}

/// One complete session between two devices. Each side sends the rights
/// requests `caps::rights_requests` gives it, as the node does, and answers
/// the other's once both committed (`caps::grant`).
fn exchange(a: &Dev, b: &Dev) {
    let (mut sa_store, mut sb_store) = (store(a), store(b));
    let (ia, ib) = (sa_store.self_id(), sb_store.self_id());
    let mut sa = Session::new(Limits::default(), Some(ib));
    let mut sb = Session::new(Limits::default(), Some(ia));
    let (mut to_a, mut to_b): (Vec<Frame>, Vec<Frame>) = (Vec::new(), Vec::new());
    let (mut held_a, mut held_b): (Vec<DirectMsg>, Vec<DirectMsg>) = (Vec::new(), Vec::new());
    fn route(
        acts: Vec<Action>,
        out: &mut Vec<Frame>,
        held: &mut Vec<DirectMsg>,
        s: &mut SqliteStore,
    ) {
        for act in acts {
            match act {
                Action::Send(f) => out.push(f),
                Action::Commit(batch) => {
                    s.commit(batch).unwrap();
                }
                Action::Direct(m) => held.push(m),
                _ => {}
            }
        }
    }
    fn asks(session: &mut Session, s: &SqliteStore, peer: &DeviceId) -> Vec<Action> {
        caps::rights_requests(s, peer)
            .unwrap()
            .into_iter()
            .flat_map(|a| {
                session.direct(DirectMsg::RightsRequest {
                    cap: a.cap,
                    month: a.month,
                    want: a.want,
                    reclaim: a.reclaim,
                })
            })
            .collect()
    }
    let acts = sa.start(&sa_store);
    route(acts, &mut to_b, &mut held_a, &mut sa_store);
    let acts = asks(&mut sa, &sa_store, &ib);
    route(acts, &mut to_b, &mut held_a, &mut sa_store);
    let acts = sb.start(&sb_store);
    route(acts, &mut to_a, &mut held_b, &mut sb_store);
    let acts = asks(&mut sb, &sb_store, &ia);
    route(acts, &mut to_a, &mut held_b, &mut sb_store);
    for _ in 0..1000 {
        if to_a.is_empty() && to_b.is_empty() {
            break;
        }
        for f in std::mem::take(&mut to_b) {
            let acts = sb.on_frame(f, &sb_store);
            route(acts, &mut to_a, &mut held_b, &mut sb_store);
        }
        for f in std::mem::take(&mut to_a) {
            let acts = sa.on_frame(f, &sa_store);
            route(acts, &mut to_b, &mut held_a, &mut sa_store);
        }
    }
    assert!(sa.is_closed() && sb.is_closed());
    for (held, s, d, peer) in [
        (held_a, &mut sa_store, a, ib),
        (held_b, &mut sb_store, b, ia),
    ] {
        for m in held {
            if let DirectMsg::RightsRequest {
                cap,
                month,
                want,
                reclaim,
            } = m
            {
                let keys = d.v.mesh_keys().unwrap();
                let ask = caps::RightsAsk {
                    cap,
                    month,
                    want,
                    reclaim,
                };
                caps::grant(s, keys.signing_key(), &AssumeNotRunning, &peer, ask).unwrap();
            }
        }
    }
    // The exchange log at the stores' own time (the node logs every
    // exchange; "active" and freshness read it).
    for (s, peer) in [(&sa_store, ib), (&sb_store, ia)] {
        s.connection()
            .execute(
                "INSERT INTO mesh_exchange_log (peer_device, at, direction, result)
                 VALUES (?1, ?2, 'outbound', 'ok')",
                params![peer.to_hex(), period::rfc3339_of(s.now_ms())],
            )
            .unwrap();
    }
}

/// `b` joins `a`'s mesh with core's pairing steps (no network).
fn join(a: &Dev, b: &Dev, name: &str) {
    let inv = a.v.mesh_invite_create(&master_pw(), None).unwrap();
    let pending = PendingIdentity::generate(name).unwrap();
    let req = pending.request();
    let now = api_tracker_core::mesh::clock::SystemClock.now_ms();
    let access =
        a.v.mesh_vault()
            .access_keys(a.v.connection(), now)
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
    exchange(a, b);
}

/// A mesh of `n` devices at `now`, `app` shared from the first and bound on
/// every other. Returns the devices and the mesh project.
fn mesh(n: usize, now: u64) -> (Vec<Dev>, MeshProjectId) {
    let devs: Vec<Dev> = (0..n).map(|_| dev(now)).collect();
    devs[0].v.mesh_init("dev-0").unwrap();
    for (i, d) in devs.iter().enumerate().skip(1) {
        join(&devs[0], d, &format!("dev-{i}"));
    }
    let keys = devs[0].v.mesh_keys().unwrap();
    let mut s0 = store(&devs[0]);
    let p = projects::share(&mut s0, keys.signing_key(), &devs[0].app, "app").unwrap();
    drop(s0);
    for d in &devs[1..] {
        exchange(&devs[0], d);
        projects::bind(&store(d), &p, &d.app).unwrap();
    }
    (devs, p)
}

fn create(d: &Dev, p: &MeshProjectId, usd: u64) -> CapId {
    let keys = d.v.mesh_keys().unwrap();
    caps::create(
        &mut store(d),
        keys.signing_key(),
        &AssumeNotRunning,
        p,
        usd * USD,
    )
    .unwrap()
    .cap_id
}

fn reconcile(d: &Dev) -> caps::ReconcileReport {
    reconcile_with(d, &AssumeNotRunning)
}

fn reconcile_with(d: &Dev, probe: &dyn GatewayProbe) -> caps::ReconcileReport {
    let keys = d.v.mesh_keys().unwrap();
    caps::reconcile(&mut store(d), keys.signing_key(), probe).unwrap()
}

/// `(view avail, local avail)` of `d` itself for `(cap, m)`.
fn avail(d: &Dev, cap: &CapId, m: Month) -> (i128, i128) {
    let s = store(d);
    let l = Ledger::of(&s);
    let c = view::cap_in(s.state(), cap).unwrap();
    let f = l.figures(&c, m);
    (
        f.device(&s.self_id()).avail,
        l.local_avail(&c, m, &f).unwrap(),
    )
}

fn figures(d: &Dev, cap: &CapId, m: Month) -> view::MonthFigures {
    let s = store(d);
    let c = view::cap_in(s.state(), cap).unwrap();
    view::month_figures(s.state(), &c, m)
}

/// A gateway daily row for `d`'s bound project, as the writer leaves it.
fn spend(d: &Dev, day_ms: u64, micros: u64) {
    let day = api_tracker_core::mesh::kinds::Day::from_unix_ms(day_ms).to_string();
    d.v.connection()
        .execute(
            "INSERT INTO gateway_usage_daily
                (day, provider_id, project_id, model, request_count, usage_event_count,
                 estimated_cost_micros, updated_at, split_known)
             VALUES (?1, 'openai', ?2, 'gpt-x', 1, 1, ?3, 'x', 1)
             ON CONFLICT(day, provider_id, project_id, model) DO UPDATE SET
                request_count = request_count + 1,
                usage_event_count = usage_event_count + 1,
                estimated_cost_micros = estimated_cost_micros + excluded.estimated_cost_micros",
            params![day, d.app, micros as i64],
        )
        .unwrap();
}

fn sum_avail_and_used(f: &view::MonthFigures) -> i128 {
    f.view.devices.values().map(|r| r.avail).sum::<i128>() + f.view.total_used as i128
}

#[test]
fn caps_months_agree_with_budget_periods_at_year_ends_and_leap_februaries() {
    for (day, hms) in [
        ("2024-02-29", "23:59:59.999"),
        ("2024-03-01", "00:00:00"),
        ("2023-12-31", "23:59:59.999"),
        ("2024-01-01", "00:00:00"),
        ("2025-02-28", "12:00:00"),
        ("2100-02-28", "23:59:59"),
        ("2100-03-01", "00:00:00.001"),
        ("2027-10-31", "23:59:59.999"),
    ] {
        let ms = at(day, hms);
        let t = time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000).unwrap();
        assert_eq!(
            period::rfc3339_of(period::month_start_ms(period::month_of(ms))),
            api_tracker_core::budget::period_start(t),
            "{day}T{hms}"
        );
    }
    assert_eq!(
        period::month_of(at("2024-02-29", "23:59:59.999")),
        month("2024-02")
    );
    assert_eq!(
        period::month_of(at("2024-01-01", "00:00:00")).prev(),
        Some(month("2023-12"))
    );
}

#[test]
fn creating_a_cap_mints_this_month_shares_it_and_one_project_gets_one_cap() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let cap = create(a, &p, 100);
    let m = month("2027-03");
    let f = figures(a, &cap, m);
    assert_eq!(f.target, Some(100 * USD));
    assert_eq!(f.owner_minted, 100 * u128::from(USD));
    // B is active (it exchanged with A): it got an equal share at once.
    assert_eq!(avail(a, &cap, m).0, 50 * USD as i128);
    exchange(a, b);
    assert_eq!(avail(b, &cap, m), (50 * USD as i128, 50 * USD as i128));
    // The escrow row of that transfer was published in the same transaction.
    let rows = escrow::rows(store(a).connection(), 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, EscrowState::Published);
    assert_eq!(rows[0].recipient(), Some(Recipient::Device(id(b))));
    // One cap per project, on either device.
    let keys = b.v.mesh_keys().unwrap();
    let err = caps::create(
        &mut store(b),
        keys.signing_key(),
        &AssumeNotRunning,
        &p,
        USD,
    )
    .unwrap_err();
    assert!(err.to_string().contains("already has a spend cap"), "{err}");
    let keys = a.v.mesh_keys().unwrap();
    let err =
        caps::create(&mut store(a), keys.signing_key(), &AssumeNotRunning, &p, 0).unwrap_err();
    assert!(err.to_string().contains("more than $0"), "{err}");
    // A second run distributes nothing more (cumulative, idempotent).
    let rep = reconcile(a);
    assert_eq!(rep.distributed_micros, 0);
    assert_eq!(rep.months_minted, 0);
    // A month later the closed escrow rows of March are forgotten (the
    // items are the record); April's are kept.
    set_time(&[a, b], at("2027-04-03", "12:00:00"));
    reconcile(a);
    let rows = escrow::rows(store(a).connection(), 10).unwrap();
    assert!(
        !rows.is_empty() && rows.iter().all(|r| r.month == month("2027-04")),
        "{rows:?}"
    );
    // The cap and its project resolve.
    let s = store(b);
    assert_eq!(caps::resolve(&s, "app").unwrap(), cap);
    assert_eq!(caps::resolve(&s, &cap.to_hex()[..10]).unwrap(), cap);
    assert!(caps::resolve(&s, "nope").is_err());
}

#[test]
fn caps_advance_minting_starts_on_day_20_with_equal_shares_for_active_devices() {
    let (devs, p) = mesh(3, at("2027-03-19", "12:00:00"));
    let all: Vec<&Dev> = devs.iter().collect();
    let cap = create(&devs[0], &p, 90);
    let april = month("2027-04");
    reconcile(&devs[0]);
    assert_eq!(
        figures(&devs[0], &cap, april).target,
        None,
        "not before day 20"
    );
    set_time(&all, at("2027-03-20", "00:00:00"));
    let rep = reconcile(&devs[0]);
    assert_eq!(rep.months_minted, 1);
    let f = figures(&devs[0], &cap, april);
    assert_eq!(
        f.target,
        Some(90 * USD),
        "next month takes the current target"
    );
    assert_eq!(f.owner_minted, 90 * u128::from(USD));
    assert_eq!(
        rep.distributed_micros,
        60 * USD,
        "two shares of 30 handed out"
    );
    for d in &devs[1..] {
        exchange(&devs[0], d);
        assert_eq!(avail(d, &cap, april).0, 30 * USD as i128);
    }
    // Minting is once per month.
    assert_eq!(reconcile(&devs[0]).months_minted, 0);
}

#[test]
fn caps_advance_minting_covers_an_owner_offline_across_the_month_boundary() {
    let (devs, p) = mesh(2, at("2027-03-10", "09:00:00"));
    let (a, b) = (&devs[0], &devs[1]);
    let cap = create(a, &p, 100);
    set_time(&[a, b], at("2027-03-25", "09:00:00"));
    reconcile(a);
    exchange(a, b);
    // A goes offline from here; B carries on into April alone.
    set_time(&[b], at("2027-04-02", "08:00:00"));
    let april = month("2027-04");
    assert_eq!(avail(b, &cap, april), (50 * USD as i128, 50 * USD as i128));
    let s = store(b);
    assert!(matches!(
        caps::try_spend(&s, &cap, april, 50 * USD).unwrap(),
        caps::SpendDecision::Allowed { .. }
    ));
    assert!(matches!(
        caps::try_spend(&s, &cap, april, 50 * USD + 1).unwrap(),
        caps::SpendDecision::Refused { .. }
    ));
    drop(s);
    // B's own spend counts at once, before it is published.
    spend(b, b.clock.now_ms(), 20 * USD);
    assert_eq!(avail(b, &cap, april).1, 30 * USD as i128);
    reconcile(b);
    assert_eq!(avail(b, &cap, april), (30 * USD as i128, 30 * USD as i128));
}

#[test]
fn caps_rebalancing_asks_below_20_percent_grants_above_half_and_is_rate_limited() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let cap = create(a, &p, 100);
    let m = month("2027-03");
    exchange(a, b);
    // B spends 45 of its 50: 5 left, under 20% of its share (10).
    spend(b, MARCH_10, 45 * USD);
    reconcile(b);
    let asks = caps::rights_requests(&store(b), &id(a)).unwrap();
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].want, 45 * USD, "back up to its share");
    assert!(!asks[0].reclaim);
    // Within 5 minutes, no second request to the same peer.
    assert!(caps::rights_requests(&store(b), &id(a)).unwrap().is_empty());
    // A grants what it holds above half its share: 50 - 25 = 25.
    let keys = a.v.mesh_keys().unwrap();
    let g = caps::grant(
        &mut store(a),
        keys.signing_key(),
        &AssumeNotRunning,
        &id(b),
        asks[0],
    )
    .unwrap();
    assert_eq!(g, 25 * USD);
    // And not twice within 5 minutes.
    let again = caps::grant(
        &mut store(a),
        keys.signing_key(),
        &AssumeNotRunning,
        &id(b),
        asks[0],
    )
    .unwrap();
    assert_eq!(again, 0);
    exchange(a, b);
    assert_eq!(avail(b, &cap, m).0, 30 * USD as i128);
    assert_eq!(avail(a, &cap, m).0, 25 * USD as i128);
    // Neither side is past a threshold now: no request, after the window too.
    set_time(&[a, b], MARCH_10 + policy::REQUEST_INTERVAL_MS + 1);
    assert!(caps::rights_requests(&store(b), &id(a)).unwrap().is_empty());
    // B spends down to 2 left, but A holds exactly half its share: nothing
    // to give.
    spend(b, MARCH_10, 28 * USD);
    reconcile(b);
    assert!(caps::rights_requests(&store(b), &id(a)).unwrap().is_empty());
    // A raises the cap by 50 (target 150, shares 75; B already has 75 from
    // A), so A now holds 75. Through real Direct frames: once B has heard of
    // the raise, the exchange carries B's request, A grants after it, and
    // the next exchange delivers the grant: 75 - ceil(75 / 2) = 37.
    let keys = a.v.mesh_keys().unwrap();
    caps::raise(
        &mut store(a),
        keys.signing_key(),
        &AssumeNotRunning,
        &cap,
        50 * USD,
    )
    .unwrap();
    exchange(a, b);
    exchange(a, b);
    exchange(a, b);
    assert_eq!(avail(b, &cap, m).0, 39_500_000, "2 + 37.50");
    let f = figures(a, &cap, m);
    assert_eq!(sum_avail_and_used(&f), f.supply(), "rights are conserved");
    assert!(f.view.devices.values().all(|r| r.clamped == 0));
}

#[test]
fn caps_raise_on_the_owner_mints_and_elsewhere_is_a_labelled_override() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let cap = create(a, &p, 100);
    let m = month("2027-03");
    let keys = a.v.mesh_keys().unwrap();
    let r = caps::raise(
        &mut store(a),
        keys.signing_key(),
        &AssumeNotRunning,
        &cap,
        20 * USD,
    )
    .unwrap();
    assert!(r.owner && !r.is_override);
    assert_eq!(
        r.distributed_micros,
        10 * USD,
        "B's share grew from 50 to 60"
    );
    let f = figures(a, &cap, m);
    assert_eq!(f.target, Some(120 * USD));
    assert_eq!(f.owner_minted, 120 * u128::from(USD));
    exchange(a, b);
    let keys = b.v.mesh_keys().unwrap();
    let r = caps::raise(
        &mut store(b),
        keys.signing_key(),
        &AssumeNotRunning,
        &cap,
        15 * USD,
    )
    .unwrap();
    assert!(!r.owner && r.is_override);
    assert_eq!(avail(b, &cap, m).0, 75 * USD as i128);
    exchange(a, b);
    let f = figures(a, &cap, m);
    assert_eq!(
        f.target,
        Some(120 * USD),
        "an override leaves the target alone"
    );
    assert_eq!(f.overrides, 15 * u128::from(USD));
    assert_eq!(f.effective_target(), Some(135 * u128::from(USD)));
    assert_eq!(
        f.pending_decrease(),
        0,
        "an override is not an excess to burn"
    );
    let report = caps::report(&store(a), Some(cap), Some(m)).unwrap();
    let row = report.caps[0].months[0]
        .devices
        .iter()
        .find(|d| d.device_id == id(b))
        .unwrap();
    assert!(row.is_override);
    assert_eq!(reconcile(a).burned_micros, 0);
    assert_eq!(reconcile(b).burned_micros, 0);
}

#[test]
fn caps_lower_burns_above_the_new_share_and_converges_to_the_target() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let cap = create(a, &p, 100);
    let m = month("2027-03");
    exchange(a, b);
    spend(b, MARCH_10, 5 * USD);
    reconcile(b);
    // Lowered on B, which is not the owner: B keeps 20 - 5 = 15 of its 45.
    let keys = b.v.mesh_keys().unwrap();
    let low = caps::lower(
        &mut store(b),
        keys.signing_key(),
        &AssumeNotRunning,
        &cap,
        40 * USD,
    )
    .unwrap();
    assert_eq!(low.burned_micros, 30 * USD);
    assert_eq!(avail(b, &cap, m).0, 15 * USD as i128);
    // The owner learns of it and burns what it holds above its share.
    exchange(a, b);
    let rep = reconcile(a);
    assert_eq!(rep.burned_micros, 30 * USD);
    exchange(a, b);
    for d in [a, b] {
        let f = figures(d, &cap, m);
        assert_eq!(f.target, Some(40 * USD));
        assert_eq!(f.supply(), 40 * USD as i128);
        assert_eq!(f.pending_decrease(), 0);
    }
    // Raising is not lowering.
    let err = caps::lower(
        &mut store(a),
        a.v.mesh_keys().unwrap().signing_key(),
        &AssumeNotRunning,
        &cap,
        40 * USD,
    )
    .unwrap_err();
    assert!(err.to_string().contains("not lower"), "{err}");
}

#[test]
fn caps_lower_below_the_spend_caps_every_device_and_the_owner_reclaims_the_rest() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let cap = create(a, &p, 100);
    let m = month("2027-03");
    exchange(a, b);
    // The owner spends 45 of its 50; then lowers the cap to 40.
    spend(a, MARCH_10, 45 * USD);
    reconcile(a);
    let keys = a.v.mesh_keys().unwrap();
    caps::lower(
        &mut store(a),
        keys.signing_key(),
        &AssumeNotRunning,
        &cap,
        40 * USD,
    )
    .unwrap();
    // What B holds is above the 45 already spent: B burns its excess above
    // its new share, and the owner reclaims the rest and burns it (which
    // comes first depends on who hears what first).
    exchange(a, b);
    reconcile(b);
    assert!(avail(b, &cap, m).0 <= 20 * USD as i128);
    for _ in 0..3 {
        set_time(&[a, b], a.clock.now_ms() + policy::REQUEST_INTERVAL_MS + 1);
        exchange(a, b);
        reconcile(a);
        reconcile(b);
    }
    exchange(a, b);
    for d in [a, b] {
        let f = figures(d, &cap, m);
        assert_eq!(
            f.supply(),
            45 * USD as i128,
            "nothing beyond what was spent"
        );
        assert_eq!(f.pending_decrease(), 0);
    }
    assert_eq!(avail(b, &cap, m).0, 0, "every device is capped");
    assert_eq!(avail(a, &cap, m).1, 0);
}

#[test]
fn caps_two_concurrent_lowers_resolve_by_last_writer_and_converge() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let cap = create(a, &p, 100);
    let m = month("2027-03");
    exchange(a, b);
    let ka = a.v.mesh_keys().unwrap();
    caps::lower(
        &mut store(a),
        ka.signing_key(),
        &AssumeNotRunning,
        &cap,
        60 * USD,
    )
    .unwrap();
    b.clock.advance(1_000);
    let kb = b.v.mesh_keys().unwrap();
    caps::lower(
        &mut store(b),
        kb.signing_key(),
        &AssumeNotRunning,
        &cap,
        30 * USD,
    )
    .unwrap();
    a.clock.advance(1_000);
    for _ in 0..4 {
        exchange(a, b);
        reconcile(a);
        reconcile(b);
    }
    exchange(a, b);
    for d in [a, b] {
        let f = figures(d, &cap, m);
        assert_eq!(f.target, Some(30 * USD), "the later lower wins");
        assert!(f.supply() <= 30 * USD as i128, "supply {}", f.supply());
        assert_eq!(f.pending_decrease(), 0);
        assert_eq!(sum_avail_and_used(&f), f.supply());
    }
}

#[test]
fn caps_reclaim_pulls_rights_back_to_the_owner_and_withholds_grants_meanwhile() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let cap = create(a, &p, 100);
    let m = month("2027-03");
    exchange(a, b);
    let err = caps::reclaim(&store(b), &cap, None).unwrap_err();
    assert!(err.to_string().contains("owner"), "{err}");
    let asked = caps::reclaim(&store(a), &cap, None).unwrap();
    assert_eq!(asked, vec![id(b)]);
    let asks = caps::rights_requests(&store(a), &id(b)).unwrap();
    assert_eq!(asks.len(), 1);
    assert!(asks[0].reclaim);
    // A device never answers itself.
    let kb = b.v.mesh_keys().unwrap();
    let g = caps::grant(
        &mut store(b),
        kb.signing_key(),
        &AssumeNotRunning,
        &id(b),
        asks[0],
    )
    .unwrap();
    assert_eq!(g, 0);
    let g = caps::grant(
        &mut store(b),
        kb.signing_key(),
        &AssumeNotRunning,
        &id(a),
        asks[0],
    )
    .unwrap();
    assert_eq!(g, 50 * USD);
    exchange(a, b);
    assert_eq!(avail(a, &cap, m).0, 100 * USD as i128);
    assert_eq!(avail(b, &cap, m).0, 0);
    // B now asks for rights; the owner grants none while reclaiming.
    set_time(&[a, b], MARCH_10 + policy::REQUEST_INTERVAL_MS + 1);
    let ask = caps::rights_requests(&store(b), &id(a)).unwrap();
    assert_eq!(ask.len(), 1);
    let ka = a.v.mesh_keys().unwrap();
    assert_eq!(
        caps::grant(
            &mut store(a),
            ka.signing_key(),
            &AssumeNotRunning,
            &id(b),
            ask[0]
        )
        .unwrap(),
        0
    );
    // Nor does the owner re-distribute to it (its share was given once).
    assert_eq!(reconcile(a).distributed_micros, 0);
}

#[test]
fn caps_removing_the_owner_freezes_the_cap_and_a_new_one_can_replace_it() {
    let (devs, p) = mesh(3, at("2027-03-10", "12:00:00"));
    let all: Vec<&Dev> = devs.iter().collect();
    let (a, b, c) = (&devs[0], &devs[1], &devs[2]);
    let cap = create(a, &p, 90);
    exchange(a, b);
    exchange(a, c);
    exchange(b, c);
    // C removes the owner (with A's whole log, so nothing A did is lost).
    c.v.mesh_device_remove(&master_pw(), &id(a).to_hex())
        .unwrap();
    exchange(b, c);
    let m = month("2027-03");
    for d in [b, c] {
        let s = store(d);
        let info = view::cap_in(s.state(), &cap).unwrap();
        assert!(info.frozen);
        assert!(!info.is_live());
    }
    // This month's rights stay usable.
    assert_eq!(avail(b, &cap, m).0, 30 * USD as i128);
    // No minting: not by an override, not next month.
    let kb = b.v.mesh_keys().unwrap();
    let err = caps::raise(
        &mut store(b),
        kb.signing_key(),
        &AssumeNotRunning,
        &cap,
        USD,
    )
    .unwrap_err();
    assert!(err.to_string().contains("frozen"), "{err}");
    set_time(&all, at("2027-03-25", "12:00:00"));
    assert_eq!(reconcile(b).months_minted, 0);
    set_time(&all, at("2027-04-02", "12:00:00"));
    reconcile(b);
    reconcile(c);
    exchange(b, c);
    assert_eq!(figures(b, &cap, month("2027-04")).supply(), 0);
    // A new cap on the project is allowed; the frozen one does not count.
    let fresh = create(b, &p, 50);
    assert_ne!(fresh, cap);
    assert_eq!(caps::resolve(&store(b), "app").unwrap(), fresh);
    // The new cap replaces the frozen one: exactly one cap is in force on
    // the project (for alerts, rebalancing and the gateway).
    let s = store(b);
    assert_eq!(
        view::cap_in(s.state(), &cap).unwrap().superseded_by,
        Some(fresh)
    );
    assert_eq!(
        view::caps_in(s.state())
            .iter()
            .filter(|c| c.in_force())
            .count(),
        1
    );
}

#[test]
fn caps_used_is_published_from_the_local_month_spend_and_a_decrease_bumps_the_epoch() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let cap = create(a, &p, 100);
    let m = month("2027-03");
    spend(a, MARCH_10, 7 * USD);
    spend(a, MARCH_10 - 3 * period::DAY_MS, 3 * USD);
    let rep = reconcile(a);
    assert_eq!(rep.used_published, 1);
    let s = store(a);
    assert_eq!(
        api_tracker_core::mesh::usage::local_month_spend_micros(&s, &p, m).unwrap(),
        10 * USD,
        "the single local-month-spend function is the source"
    );
    drop(s);
    assert_eq!(
        figures(a, &cap, m).device(&id(a)).used,
        10 * u128::from(USD)
    );
    assert_eq!(reconcile(a).used_published, 0, "unchanged: nothing new");
    // Local data deleted (a deletion tool): the decrease propagates.
    a.v.connection()
        .execute("DELETE FROM gateway_usage_daily", [])
        .unwrap();
    assert_eq!(reconcile(a).used_published, 1);
    exchange(a, b);
    assert_eq!(figures(b, &cap, m).device(&id(a)).used, 0);
    let s = store(b);
    let key = format!("{cap}/{m}");
    let bytes: Vec<u8> = s
        .connection()
        .query_row(
            "SELECT bytes FROM mesh_items WHERE kind = 'cap.used' AND item_key = ?1",
            [key],
            |r| r.get(0),
        )
        .unwrap();
    let body = api_tracker_core::mesh::SignedItem::from_wire(&bytes)
        .unwrap()
        .decode_unverified()
        .unwrap();
    assert_eq!(body.payload["epoch"], 1);
    // Unbound: what was published stays.
    spend(b, MARCH_10, 4 * USD);
    reconcile(b);
    projects::unbind(b.v.connection(), &b.app).unwrap();
    b.v.connection()
        .execute("DELETE FROM gateway_usage_daily", [])
        .unwrap();
    assert_eq!(reconcile(b).used_published, 0);
    assert_eq!(figures(b, &cap, m).device(&id(b)).used, 4 * u128::from(USD));
}

fn enforce(d: &Dev) {
    d.v.connection()
        .execute(
            "INSERT INTO gateway_config (id, enabled, cap_enforcement, created_at, updated_at)
             VALUES ('gateway', 1, 1, 'x', 'x')
             ON CONFLICT(id) DO UPDATE SET cap_enforcement = 1",
            [],
        )
        .unwrap();
}

#[test]
fn caps_escrow_publishes_at_once_unfenced_and_waits_for_the_gateway_ack_when_fenced() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let m = month("2027-03");
    enforce(a);
    // Enforcement on and the gateway running: the share for B is reserved,
    // not published.
    let ka = a.v.mesh_keys().unwrap();
    let cap = caps::create(
        &mut store(a),
        ka.signing_key(),
        &AssumeRunning,
        &p,
        100 * USD,
    )
    .unwrap()
    .cap_id;
    let open = escrow::open_rows(store(a).connection()).unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].state, EscrowState::Pending);
    assert_eq!(open[0].amount_micros, 50 * USD);
    assert_eq!(
        avail(a, &cap, m),
        (100 * USD as i128, 50 * USD as i128),
        "reserved"
    );
    exchange(a, b);
    assert_eq!(avail(b, &cap, m).0, 0, "nothing published to B");
    // Rounds without an ack carry it; past 15 s it is reported as waiting.
    assert_eq!(reconcile_with(a, &AssumeRunning).escrow_published, 0);
    a.clock.advance(policy::ACK_WAIT_MS + 1);
    let rep = reconcile_with(a, &AssumeRunning);
    assert_eq!((rep.escrow_published, rep.escrow_waiting), (0, 1));
    assert_eq!(
        rep.distributed_micros, 0,
        "the reservation is not given twice"
    );
    // The gateway (here a fake acker) counts it and acknowledges.
    let n = escrow::ack(store(a).connection(), &[open[0].id.clone()], 7).unwrap();
    assert_eq!(n, 1);
    let rep = reconcile_with(a, &AssumeRunning);
    assert_eq!(rep.escrow_published, 1);
    let row = &escrow::rows(store(a).connection(), 1).unwrap()[0];
    assert_eq!(
        (row.state, row.acked_generation),
        (EscrowState::Published, Some(7))
    );
    exchange(a, b);
    assert_eq!(avail(b, &cap, m).0, 50 * USD as i128);
    // In that exchange B (holding nothing yet) asked A for rights, and A
    // granted after it through a probe that finds no gateway running:
    // enforcement on, but published at once.
    let latest = &escrow::rows(store(a).connection(), 1).unwrap()[0];
    assert_eq!(
        (latest.state, latest.amount_micros),
        (EscrowState::Published, 25 * USD)
    );
    assert!(escrow::open_rows(store(a).connection()).unwrap().is_empty());
    // A pending row whose month ended is cancelled.
    let s = store(a);
    let id_row = {
        s.connection()
            .execute(
                "INSERT INTO mesh_cap_escrow (id, cap_id, month, to_device, amount_micros, state,
                     created_at, updated_at)
                 VALUES ('old', ?1, '2027-02', 'burn', 5, 'pending', 'x', 'x')",
                [cap.to_hex()],
            )
            .unwrap();
        "old"
    };
    drop(s);
    let rep = reconcile_with(a, &AssumeRunning);
    assert_eq!(rep.escrow_cancelled, 1);
    // Cancelled, and then forgotten with the ended month's closed rows.
    let left: i64 = store(a)
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM mesh_cap_escrow WHERE id = ?1",
            [id_row],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(left, 0);
}

#[test]
fn caps_two_caps_created_apart_resolve_to_the_first_and_the_other_is_superseded() {
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let first = create(a, &p, 100);
    b.clock.advance(5_000);
    let second = create(b, &p, 70);
    exchange(a, b);
    for d in [a, b] {
        let s = store(d);
        let c = view::cap_in(s.state(), &second).unwrap();
        assert_eq!(c.superseded_by, Some(first));
        assert!(view::cap_in(s.state(), &first).unwrap().is_live());
        assert_eq!(caps::resolve(&s, "app").unwrap(), first);
    }
    // The superseded cap is not minted ahead or changed again.
    set_time(&[a, b], at("2027-03-21", "10:00:00"));
    reconcile(b);
    assert_eq!(figures(b, &second, month("2027-04")).owner_minted, 0);
    let kb = b.v.mesh_keys().unwrap();
    let err = caps::raise(
        &mut store(b),
        kb.signing_key(),
        &AssumeNotRunning,
        &second,
        USD,
    )
    .unwrap_err();
    assert!(err.to_string().contains("created first"), "{err}");
}

#[test]
fn caps_alerts_fire_at_80_and_100_percent_through_the_alert_system_without_budgets() {
    // The monitor reads the store on the system clock: real dates here.
    let now = api_tracker_core::mesh::clock::SystemClock.now_ms();
    let (devs, p) = mesh(1, now);
    let a = &devs[0];
    let keys = a.v.mesh_keys().unwrap();
    let cap = caps::create(
        &mut a.v.mesh_open_store().unwrap(),
        keys.signing_key(),
        &AssumeNotRunning,
        &p,
        10 * USD,
    )
    .unwrap()
    .cap_id;
    let m = period::month_of(now);
    let open = |kind: &str| -> Vec<alerts::Alert> {
        alerts::list(a.v.connection(), false)
            .unwrap()
            .into_iter()
            .filter(|x| x.kind == kind)
            .collect()
    };
    a.v.run_monitor().unwrap();
    assert!(open("mesh_spend_cap").is_empty());
    spend(a, now, 8_500_000);
    a.v.run_monitor().unwrap();
    let got = open("mesh_spend_cap");
    assert_eq!(got.len(), 1);
    assert!(got[0].title.contains("85%"), "{}", got[0].title);
    assert!(got[0].detail.contains("Estimated"), "{}", got[0].detail);
    assert!(
        got[0].detail.contains("as of the last exchange"),
        "{}",
        got[0].detail
    );
    assert!(got[0].evidence.contains(&format!("cap={cap} month={m}")));
    spend(a, now, 2_000_000);
    let summary = a.v.run_monitor().unwrap();
    let got = open("mesh_spend_cap");
    assert_eq!(got.len(), 2, "80 and 100");
    assert!(got.iter().any(|x| x.severity == "high"));
    // Dedup: a further run creates nothing new.
    let again = a.v.run_monitor().unwrap();
    assert!(again.alerts_created <= summary.alerts_created);
    assert_eq!(open("mesh_spend_cap").len(), 2);
    // Budgets are not involved: no budget alert, no budget row.
    assert!(open("over_budget").is_empty());
    let budgets: i64 =
        a.v.connection()
            .query_row("SELECT COUNT(*) FROM budgets", [], |r| r.get(0))
            .unwrap_or(0);
    assert_eq!(budgets, 0);
    // Raised well above the spend, both alerts resolve at the next run.
    caps::raise(
        &mut a.v.mesh_open_store().unwrap(),
        keys.signing_key(),
        &AssumeNotRunning,
        &cap,
        100 * USD,
    )
    .unwrap();
    a.v.run_monitor().unwrap();
    assert!(open("mesh_spend_cap").is_empty());
}

#[test]
fn caps_enforcement_follows_the_cap_in_force_and_all_off_clears_every_switch() {
    use api_tracker_core::mesh::caps::gate::{self, GateRead};
    let (devs, p) = mesh(2, MARCH_10);
    let (a, b) = (&devs[0], &devs[1]);
    let first = create(a, &p, 100);
    b.clock.advance(5_000);
    let second = create(b, &p, 70);
    // B switches its own (still unchallenged) cap on.
    b.v.mesh_cap_enforce(&master_pw(), Some(&second.to_hex()), true)
        .unwrap();
    exchange(a, b);
    // A's cap was first: B's is superseded, and the switch carries over to
    // the cap now in force there.
    let snap = |d: &Dev| match gate::gate_snapshot(d.v.connection(), MARCH_10, &[]).unwrap() {
        GateRead::Ready(i) => i,
        GateRead::NoMesh => panic!("no mesh"),
    };
    let caps_b = snap(b).caps;
    assert_eq!(caps_b.len(), 1);
    assert_eq!(caps_b[0].cap_id, first);
    assert!(caps_b[0].enforced, "inherited from the superseded cap");
    assert!(!snap(a).caps[0].enforced, "A never switched it on");
    // A superseded cap cannot be switched on directly.
    let err =
        b.v.mesh_cap_enforce(&master_pw(), Some(&second.to_hex()), true)
            .unwrap_err();
    assert!(err.to_string().contains("another cap is in force"), "{err}");
    // `--all off` clears every switch, the superseded cap's included.
    b.v.mesh_cap_enforce(&master_pw(), None, false).unwrap();
    assert!(gate::enforced_caps(b.v.connection()).unwrap().is_empty());
    assert!(!escrow::enforcement_on(b.v.connection()).unwrap());
    assert!(!snap(b).caps[0].enforced);
}
