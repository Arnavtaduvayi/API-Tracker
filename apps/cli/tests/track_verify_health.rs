//! `NEW-01` / `VER-02` regression suite: the CLI must not claim verification
//! from a liveness-blind cached state.
//!
//! The fresh audit found `tethra track` printing `✓ Tracking verified` and
//! returning exit 0 whenever `verify::check_traffic` reported `Observed`.
//! That predicate switches on the cached `tracking_setups.state` column
//! after a `GatewayLiveness::Unknown` refresh, so it survived stopping the
//! gateway, deleting the route and deleting the project link. The same file
//! stated the opposite rule 200 lines later for `track status`, and the
//! desktop had already fixed exactly this defect and named it — the CLI, the
//! documented fallback in the supported journey, had neither the rule nor a
//! test.
//!
//! Every test here drives the REAL `tethra` binary. Nothing installs a
//! launchd job: a foreground `tethra gateway serve` child makes
//! `plan::plan` emit `ServiceAction::AlreadyRunning`, so apply never reaches
//! the service-lifecycle step. See `tests/common/mod.rs`.
//!
//! The suite is split in two layers on purpose:
//!
//! * **Layer A** drives the verify loop itself, which is where the defect
//!   was. It needs a live gateway, so it is the expensive half.
//! * **Layer B** drives `track status` against a synthesised configured
//!   setup with no gateway process at all. It is cheap, deterministic, and
//!   it closes the audit's other observation — that *no* test anywhere
//!   exercised `track status` against a configured setup.
//!
//! Both layers gate on the same shared resolver
//! (`api_tracker_tracking::health::resolve`), which is the point: there is
//! one rule, and reverting it fails tests in both halves.

#![cfg(unix)]

mod common;

use common::*;

/// Short pacing so a failure case does not sit through the real two-minute
/// window. The DECISION is never overridable — only the cadence.
fn fast_pacing(cmd: &mut std::process::Command) {
    cmd.env("TETHRA_TRACK_POLL_SECS", "1")
        .env("TETHRA_TRACK_WAIT_SECS", "25");
}

const VERIFIED: &str = "✓ Tracking verified";

// ---------------------------------------------------------------------------
// Layer A — the verify loop, against a real foreground gateway
// ---------------------------------------------------------------------------

/// Run `track --yes <dir>` as a child, wait until it reaches the verify
/// loop, run `act`, then return (exit code, full stdout).
fn track_and_act(tv: &TestVault, dir: &std::path::Path, act: impl FnOnce()) -> (i32, String) {
    track_cmd_and_act(tv.raw(), dir, act)
}

fn track_cmd_and_act(
    mut cmd: std::process::Command,
    dir: &std::path::Path,
    act: impl FnOnce(),
) -> (i32, String) {
    cmd.args(["track", "--yes"])
        .arg(dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    fast_pacing(&mut cmd);
    let mut child = cmd.spawn().expect("spawning track");
    let reader = wait_for_line(&mut child, "Waiting for traffic");
    act();
    let rest = drain(reader);
    let status = child.wait().expect("waiting for track");
    (status.code().unwrap_or(-1), rest)
}

#[test]
fn historical_traffic_with_a_dead_gateway_is_never_reported_as_verified() {
    let tv = TestVault::new();
    let dir = tv.project_dir("myapp");
    write_fixture(&dir);
    let gw = tv.spawn_gateway();

    let data = tv.data_dir.clone();
    let dir2 = dir.clone();
    let (code, out) = track_and_act(&tv, &dir, move || {
        // Kill FIRST, then plant: the observation must land in a world
        // where liveness is already Down, so the assertion cannot race the
        // poll. This is the audit's decisive reproduction.
        gw.kill();
        let conn = api_tracker_core::db::open(&data.join("vault.db")).unwrap();
        let setup = setup_for(&conn, &dir2.canonicalize().unwrap());
        plant_observation(&conn, &setup.project_id, "api.openai.com", &now());
    });

    assert!(
        !out.contains(VERIFIED),
        "traffic observed once must not read as verified while the gateway is down:\n{out}"
    );
    assert!(
        out.contains("not reaching your APIs"),
        "the present-tense failure must be named:\n{out}"
    );
    assert!(
        out.contains("observed previously"),
        "the historical fact is still worth printing, under its own heading:\n{out}"
    );
    assert_eq!(
        code, 2,
        "a script gating on `tethra track` must not be told yes:\n{out}"
    );
}

#[test]
fn a_removed_route_is_never_reported_as_verified() {
    let tv = TestVault::new();
    let dir = tv.project_dir("myapp");
    write_fixture(&dir);
    let _gw = tv.spawn_gateway();

    let data = tv.data_dir.clone();
    let dir2 = dir.clone();
    let (code, out) = track_and_act(&tv, &dir, move || {
        let conn = api_tracker_core::db::open(&data.join("vault.db")).unwrap();
        conn.execute(
            "DELETE FROM gateway_routes WHERE route_prefix = 'openai'",
            [],
        )
        .unwrap();
        let setup = setup_for(&conn, &dir2.canonicalize().unwrap());
        plant_observation(&conn, &setup.project_id, "api.openai.com", &now());
    });

    assert!(!out.contains(VERIFIED), "{out}");
    assert!(
        out.contains("is gone"),
        "the configuration change is named:\n{out}"
    );
    assert_eq!(code, 2, "{out}");
}

#[test]
fn a_removed_project_link_is_never_reported_as_verified() {
    let tv = TestVault::new();
    let dir = tv.project_dir("myapp");
    write_fixture(&dir);
    let _gw = tv.spawn_gateway();

    let data = tv.data_dir.clone();
    let dir2 = dir.clone();
    let (code, out) = track_and_act(&tv, &dir, move || {
        let conn = api_tracker_core::db::open(&data.join("vault.db")).unwrap();
        let setup = setup_for(&conn, &dir2.canonicalize().unwrap());
        conn.execute(
            "DELETE FROM gateway_project_links WHERE project_id = ?1",
            [&setup.project_id],
        )
        .unwrap();
        plant_observation(&conn, &setup.project_id, "api.openai.com", &now());
    });

    assert!(!out.contains(VERIFIED), "{out}");
    assert!(out.contains("is gone"), "{out}");
    assert_eq!(code, 2, "{out}");
}

/// The anti-vacuity control. A "fix" that reported failure unconditionally
/// would satisfy every other test in this file and break the product.
#[test]
fn fresh_traffic_with_every_dependency_healthy_is_verified_and_exits_zero() {
    let tv = TestVault::new();
    let dir = tv.project_dir("myapp");
    write_fixture(&dir);
    let _gw = tv.spawn_gateway();

    let data = tv.data_dir.clone();
    let dir2 = dir.clone();
    let (code, out) = track_and_act(&tv, &dir, move || {
        let conn = api_tracker_core::db::open(&data.join("vault.db")).unwrap();
        let setup = setup_for(&conn, &dir2.canonicalize().unwrap());
        plant_observation(&conn, &setup.project_id, "api.openai.com", &now());
    });

    assert!(
        out.contains(VERIFIED),
        "a live gateway with fresh traffic and an intact configuration IS a success:\n{out}"
    );
    assert_eq!(code, 0, "{out}");
}

/// Attribution is not forwarding. A gateway serving without a matching key
/// still forwards and still records, so tracking is working — the pause is
/// reported beside the success, never folded into it (SI-11/SI-12).
#[test]
fn attribution_paused_while_forwarding_is_healthy_still_verifies() {
    let tv = TestVault::new();
    let dir = tv.project_dir("myapp");
    write_fixture(&dir);
    // `gateway serve` without `--with-attribution` installs no matching key,
    // and `track` run from a persisted session rather than TETHRA_PASSWORD
    // skips attribution too (O-22-3) — so the gateway forwards and records
    // while holding no matching key. That is exactly "attribution paused".
    let session = tv.unlock_session();
    let _gw = tv.spawn_gateway();

    let data = tv.data_dir.clone();
    let dir2 = dir.clone();
    let mut cmd = tv.raw_no_password();
    cmd.env("TETHRA_SESSION", &session);
    let (code, out) = track_cmd_and_act(cmd, &dir, move || {
        let conn = api_tracker_core::db::open(&data.join("vault.db")).unwrap();
        let setup = setup_for(&conn, &dir2.canonicalize().unwrap());
        plant_observation(&conn, &setup.project_id, "api.openai.com", &now());
    });

    assert!(out.contains(VERIFIED), "{out}");
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("attribution is paused"),
        "the degraded attribution must be disclosed beside the success:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// Layer B — `track status` against a synthesised configured setup
// ---------------------------------------------------------------------------

/// `track status` on a configured setup, with no gateway process running.
fn status_of(tv: &TestVault, dir: &std::path::Path) -> (i32, String) {
    let out = tv
        .cmd()
        .args(["track", "status"])
        .arg(dir)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn status_reports_a_dead_gateway_after_historical_success() {
    let tv = TestVault::new();
    let dir = tv.project_dir("b1").canonicalize().unwrap();
    let conn = tv.conn();
    let setup = configured_setup(&conn, "p1", &dir, &["openai"]);
    plant_observation(&conn, "p1", "api.openai.com", &recent());
    drop(setup);
    drop(conn);

    let (code, out) = status_of(&tv, &dir);
    assert!(out.contains("not reaching your APIs"), "{out}");
    assert!(!out.contains("Now: tracking verified and active"), "{out}");
    assert_eq!(
        code, 2,
        "verified previously is deliberately a non-zero exit:\n{out}"
    );
}

#[test]
fn status_reports_a_newer_failure_over_an_older_observation() {
    let tv = TestVault::new();
    let dir = tv.project_dir("b2").canonicalize().unwrap();
    let conn = tv.conn();
    let setup = configured_setup(&conn, "p2", &dir, &["openai"]);
    plant_observation(&conn, "p2", "api.openai.com", &recent());
    // A repair that failed AFTER the observation. `refresh_with` must not
    // let the older success erase it (ZFT-006).
    let later = api_tracker_core::clock::now_rfc3339();
    conn.execute(
        "UPDATE tracking_setups SET state = 'needs_attention',
             attention_reason = 'apply_failed:EnsureRoutes', attention_at = ?2
         WHERE id = ?1",
        rusqlite::params![setup.id, later],
    )
    .unwrap();
    drop(conn);

    let (code, out) = status_of(&tv, &dir);
    assert!(out.contains("apply_failed:EnsureRoutes"), "{out}");
    assert!(!out.contains(VERIFIED), "{out}");
    assert_eq!(code, 2, "{out}");
}

/// An observation older than the freshness window is history, not health.
/// This is the case none of the audit's own scenarios reaches, and it is
/// what kills a "gate on `observed_ever` rather than `fresh`" mutation.
#[test]
fn status_reports_a_stale_observation_as_history_not_health() {
    let tv = TestVault::new();
    let dir = tv.project_dir("b3").canonicalize().unwrap();
    let conn = tv.conn();
    configured_setup(&conn, "p3", &dir, &["openai"]);
    plant_observation(&conn, "p3", "api.openai.com", &stale());
    drop(conn);

    let (code, out) = status_of(&tv, &dir);
    assert!(!out.contains("Now: tracking verified and active"), "{out}");
    assert_eq!(code, 2, "{out}");
}

/// A setup re-applied since its last observation has a NEW verification
/// session, so the previous session's traffic is not evidence about this
/// one.
#[test]
fn status_does_not_carry_a_previous_sessions_traffic_into_a_new_one() {
    let tv = TestVault::new();
    let dir = tv.project_dir("b4").canonicalize().unwrap();
    let conn = tv.conn();
    configured_setup(&conn, "p4", &dir, &["openai"]);
    plant_observation(&conn, "p4", "api.openai.com", &recent());
    // Re-apply: `upsert_setup` mints a fresh verification session, bumps the
    // config generation and clears `applied_at`.
    configured_setup(&conn, "p4", &dir, &["openai"]);
    let setup = setup_for(&conn, &dir);
    let now = api_tracker_core::clock::now_rfc3339();
    conn.execute(
        "UPDATE tracking_setups SET applied_at = ?2 WHERE id = ?1",
        rusqlite::params![setup.id, now],
    )
    .unwrap();
    drop(conn);

    let (code, out) = status_of(&tv, &dir);
    assert!(!out.contains("Now: tracking verified and active"), "{out}");
    assert_eq!(code, 2, "{out}");
}

/// The machine-readable shape the desktop and any script depend on. The
/// audit found nothing pinning it: `current` is the present-tense answer a
/// caller must act on, `history` is beside it, never instead of it.
#[test]
fn status_json_separates_current_health_from_history() {
    let tv = TestVault::new();
    let dir = tv.project_dir("b5").canonicalize().unwrap();
    let conn = tv.conn();
    configured_setup(&conn, "p5", &dir, &["openai"]);
    plant_observation(&conn, "p5", "api.openai.com", &recent());
    drop(conn);

    let out = tv
        .cmd()
        .args(["--json", "track", "status"])
        .arg(&dir)
        .output()
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("track status --json must emit JSON");
    assert_eq!(
        v["gateway_running"], false,
        "no gateway is running in this test"
    );
    assert_eq!(
        v["current"]["kind"], "verified_previously_gateway_down",
        "the present-tense answer must name the dead gateway: {v}"
    );
    assert!(
        v["history"]["session_first_observed_at"].is_string(),
        "the historical fact survives, under its own key: {v}"
    );
}
