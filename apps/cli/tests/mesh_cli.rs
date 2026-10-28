//! `tethra mesh init` / `tethra mesh status` against the real binary, in a
//! throwaway vault with an isolated `HOME` and `TETHRA_DIR` (ADR 0031,
//! Increment 03). Nothing listens and nothing leaves the machine.

mod common;

use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, VaultPaths};
use common::{TestVault, MASTER_PW};
use serde_json::Value;

const BACKUP_PW: &str = "mesh-cli-backup-password-01";

fn run(tv: &TestVault, args: &[&str]) -> (bool, String, String) {
    let out = tv.cmd().args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json(tv: &TestVault, args: &[&str]) -> Value {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let (ok, stdout, stderr) = run(tv, &full);
    assert!(ok, "{args:?} failed: {stderr}");
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

/// Any run of 64 lowercase hex characters: the shape of every key this
/// device holds, public or private. Mesh output never prints one.
fn has_hex64(s: &str) -> bool {
    let mut run = 0;
    for c in s.chars() {
        if c.is_ascii_digit() || ('a'..='f').contains(&c) {
            run += 1;
            if run >= 64 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn status_before_init_is_a_clear_message_and_exits_zero() {
    let tv = TestVault::new();
    let (ok, stdout, _) = run(&tv, &["mesh", "status"]);
    assert!(ok);
    assert!(stdout.contains("not part of a mesh"), "{stdout}");
    assert!(stdout.contains("tethra mesh init"), "{stdout}");
    let v = json(&tv, &["mesh", "status"]);
    assert_eq!(v, serde_json::json!({ "initialized": false }));
}

#[test]
fn init_then_status_in_human_and_json_form_without_any_key_material() {
    let tv = TestVault::new();
    let mut transcript = String::new();

    let (ok, stdout, stderr) = run(&tv, &["mesh", "init", "--name", "dev-a"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("Started a new mesh"), "{stdout}");
    assert!(stdout.contains("dev-a"), "{stdout}");
    transcript.push_str(&stdout);
    transcript.push_str(&stderr);

    let (ok, stdout, stderr) = run(&tv, &["mesh", "status"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("marker ok"), "{stdout}");
    assert!(stdout.contains("dev-a"), "{stdout}");
    assert!(stdout.contains("roster.add 1"), "{stdout}");
    transcript.push_str(&stdout);
    transcript.push_str(&stderr);

    let st = json(&tv, &["mesh", "status"]);
    transcript.push_str(&st.to_string());
    assert_eq!(st["initialized"], true);
    assert_eq!(st["roster_size"], 1);
    assert_eq!(st["next_seq"], 3);
    assert_eq!(st["marker"], "ok");
    assert_eq!(st["self_forked"], false);
    assert_eq!(st["devices"][0]["name"], "dev-a");
    assert_eq!(st["devices"][0]["is_self"], true);
    assert_eq!(st["items_by_kind"]["roster.add"], 1);
    assert_eq!(st["items_by_kind"]["device.info"], 1);
    assert_eq!(st["genesis_device"], st["device_id"]);
    let device = st["device_id"].as_str().unwrap().to_owned();
    assert_eq!(st["vv"][&device], 2);

    // A second init is refused, with the typed error's message.
    let (ok, _, stderr) = run(&tv, &["mesh", "init", "--name", "dev-b"]);
    assert!(!ok);
    assert!(stderr.contains("already part of a mesh"), "{stderr}");
    assert_eq!(
        stderr.matches("already part of a mesh").count(),
        1,
        "{stderr}"
    );
    transcript.push_str(&stderr);
    let (ok, _, stderr) = run(&tv, &["--json", "mesh", "init"]);
    assert!(!ok);
    transcript.push_str(&stderr);

    // No key, public or private, appears anywhere in what was printed.
    assert!(
        !has_hex64(&transcript),
        "a 64-hex run was printed:\n{transcript}"
    );
    let unlocked = vault::unlock_vault(
        &VaultPaths::new(tv.data_dir.clone()),
        &SecretString::from(MASTER_PW),
    )
    .unwrap();
    let keys = unlocked.mesh_keys().unwrap();
    for secret in [
        to_hex(&*keys.signing_key().expose_secret_bytes()),
        to_hex(keys.expose_noise_secret()),
        to_hex(keys.expose_access_key()),
        keys.signing_key().public_key().to_hex(),
        keys.noise_pub().to_hex(),
    ] {
        assert!(!transcript.contains(&secret), "key material in the output");
    }
}

#[test]
fn a_device_name_is_validated_and_defaults_to_the_host_name() {
    let tv = TestVault::new();
    let (ok, _, stderr) = run(&tv, &["mesh", "init", "--name", "   "]);
    assert!(!ok);
    assert!(stderr.contains("device name"), "{stderr}");
    assert!(!json(&tv, &["mesh", "status"])["initialized"]
        .as_bool()
        .unwrap());
    // Without --name the device is still named (the host name, or a
    // placeholder when there is none).
    let v = json(&tv, &["mesh", "init"]);
    let name = v["device_name"].as_str().unwrap();
    assert!(
        !name.trim().is_empty() && name.chars().count() <= 64,
        "{name}"
    );
    assert!(v.get("sign_pub").is_none() && v.get("noise_pub").is_none());
}

#[test]
fn a_restored_backup_leaves_the_mesh_and_can_start_a_new_one() {
    let tv = TestVault::new();
    let first = json(&tv, &["mesh", "init", "--name", "dev-a"]);
    let backup = tv.data_dir.parent().unwrap().join("mesh.backup");
    let backup = backup.to_str().unwrap();
    let out = tv
        .cmd()
        .env("TETHRA_BACKUP_PASSWORD", BACKUP_PW)
        .args(["backup", "create", backup])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let other = tv.data_dir.parent().unwrap().join("restored");
    let out = tv
        .cmd()
        .env("TETHRA_DIR", &other)
        .env("TETHRA_BACKUP_PASSWORD", BACKUP_PW)
        .args(["backup", "restore", backup])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("must pair again"), "{stdout}");

    let status = tv
        .cmd()
        .env("TETHRA_DIR", &other)
        .args(["--json", "mesh", "status"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(v["initialized"], false);
    let fresh = tv
        .cmd()
        .env("TETHRA_DIR", &other)
        .args(["--json", "mesh", "init", "--name", "dev-restored"])
        .output()
        .unwrap();
    let fresh: Value = serde_json::from_slice(&fresh.stdout).unwrap();
    assert_ne!(fresh["device_id"], first["device_id"]);
    // The original device is untouched.
    assert_eq!(
        json(&tv, &["mesh", "status"])["device_id"],
        first["device_id"]
    );
}

/// `tethra mesh serve --listen 127.0.0.1:0` as a child; killed on drop.
struct Serving {
    child: std::process::Child,
    addr: String,
}

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn serve(tv: &TestVault) -> Serving {
    use std::io::BufRead;
    let mut child = tv
        .raw()
        .args(["mesh", "serve", "--listen", "127.0.0.1:0"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addr = line
        .trim()
        .strip_prefix("Listening on ")
        .unwrap_or_else(|| panic!("unexpected serve output: {line}"))
        .to_owned();
    Serving { child, addr }
}

fn devices(tv: &TestVault) -> Vec<Value> {
    json(tv, &["mesh", "devices"]).as_array().unwrap().clone()
}

#[test]
fn invite_join_devices_remove_and_leave_across_three_devices() {
    let a = TestVault::new();
    run(&a, &["mesh", "init", "--name", "dev-a"]);
    let server = serve(&a);

    // A invites B; the invite is printed once, with a warning.
    let (ok, invite, warn) = run(&a, &["mesh", "invite", "--addr", &server.addr]);
    assert!(ok, "{warn}");
    let invite = invite.trim().to_owned();
    assert!(invite.starts_with("tethra-mesh-invite:v1:"));
    assert!(warn.contains("password"), "{warn}");
    let code = invite["tethra-mesh-invite:v1:".len()..][..32].to_owned();
    let mut later = String::new();

    let b = TestVault::new();
    let (ok, out, err) = run(&b, &["mesh", "join", &invite, "--name", "dev-b"]);
    assert!(ok, "{err}");
    assert!(out.contains("Joined mesh"), "{out}");
    later.push_str(&out);
    later.push_str(&err);
    // The same invite cannot be used twice.
    let c = TestVault::new();
    let (ok, out, err) = run(&c, &["mesh", "join", &invite, "--name", "dev-c"]);
    assert!(!ok);
    later.push_str(&out);
    later.push_str(&err);

    assert_eq!(devices(&a).len(), 2);
    assert_eq!(devices(&b).len(), 2);

    // A second invite, as JSON, admits C.
    let inv = json(&a, &["mesh", "invite", "--addr", &server.addr]);
    let invite2 = inv["invite"].as_str().unwrap().to_owned();
    let (ok, out, err) = run(&c, &["mesh", "join", &invite2, "--name", "dev-c"]);
    assert!(ok, "{err}");
    later.push_str(&out);
    later.push_str(&err);
    // B learns of C through A.
    let (ok, out, err) = run(&b, &["mesh", "replicate", "--peer", &server.addr]);
    assert!(ok, "{err}");
    later.push_str(&out);
    assert_eq!(devices(&b).len(), 3);

    // A removes C: C is refused from then on.
    let c_id = json(&c, &["mesh", "status"])["device_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (ok, out, err) = run(&a, &["mesh", "remove", &c_id[..10], "--yes"]);
    assert!(ok, "{err}");
    assert!(out.contains("epoch 2"), "{out}");
    let (ok, _, err) = run(&c, &["mesh", "replicate", "--peer", &server.addr]);
    assert!(!ok, "a removed device must be refused");
    later.push_str(&err);
    let on_a = devices(&a);
    assert!(on_a
        .iter()
        .any(|d| d["device_id"] == c_id.as_str() && d["removed"] == true));

    // B leaves, telling A on the way out.
    let (ok, out, err) = run(
        &b,
        &["--json", "mesh", "leave", "--yes", "--peer", &server.addr],
    );
    assert!(ok, "{err}");
    let left: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(left["delivered"], true);
    assert_eq!(json(&b, &["mesh", "status"])["initialized"], false);
    let b_removed = devices(&a).iter().filter(|d| d["removed"] == true).count();
    assert_eq!(b_removed, 2, "A sees C removed and B gone");

    // The invite code never appears again after it was shown.
    for tv in [&a, &b, &c] {
        let (_, out, err) = run(tv, &["--json", "mesh", "devices"]);
        later.push_str(&out);
        later.push_str(&err);
    }
    assert!(!later.contains(&code), "the invite code was printed again");
    assert!(!has_hex64(&later), "key-shaped hex in the output");
    drop(server);
}

/// `tethra mesh serve` as a full node with a short round interval (the
/// debug-only `TETHRA_MESH_INTERVAL_MS`).
fn serve_node(tv: &TestVault, interval_ms: u64) -> Serving {
    use std::io::BufRead;
    let mut child = tv
        .raw()
        .args(["mesh", "serve", "--listen", "127.0.0.1:0"])
        .env("TETHRA_MESH_INTERVAL_MS", interval_ms.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addr = line
        .trim()
        .strip_prefix("Listening on ")
        .unwrap_or_else(|| panic!("unexpected serve output: {line}"))
        .to_owned();
    Serving { child, addr }
}

fn wait_for(secs: u64, mut f: impl FnMut() -> bool, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn peers_node_status_doctor_replicate_and_stop_from_the_cli() {
    let a = TestVault::new();
    run(&a, &["mesh", "init", "--name", "dev-a"]);
    let node_a = serve_node(&a, 300);
    let inv = json(&a, &["mesh", "invite", "--addr", &node_a.addr]);
    let b = TestVault::new();
    let (ok, _, err) = run(
        &b,
        &[
            "mesh",
            "join",
            inv["invite"].as_str().unwrap(),
            "--name",
            "dev-b",
        ],
    );
    assert!(ok, "{err}");

    // peer add / list / remove. Joining already made A's address a peer.
    let added = json(&b, &["mesh", "peer", "add", &node_a.addr]);
    assert_eq!(added["addr"], node_a.addr.as_str());
    assert_eq!(added["added"], false);
    let extra = json(&b, &["mesh", "peer", "add", "Spare-Box.local:7420"]);
    assert_eq!(extra["addr"], "spare-box.local:7420");
    assert_eq!(extra["added"], true);
    for bad in ["laptop", "0.0.0.0:7420", "x y:1"] {
        let (ok, _, err) = run(&b, &["mesh", "peer", "add", bad]);
        assert!(!ok && err.contains("HOST:PORT"), "{bad}: {err}");
    }
    let removed = json(&b, &["mesh", "peer", "remove", "spare-box.local:7420"]);
    assert_eq!(removed["removed"], true);
    let list = json(&b, &["mesh", "peer", "list"]);
    let rows = list.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["device_name"], "dev-a");
    for field in [
        "addr",
        "device_id",
        "device_name",
        "source",
        "last_attempt_at",
        "last_success_at",
        "failures",
        "unreachable_since",
        "last_error",
    ] {
        assert!(rows[0].get(field).is_some(), "peer list lacks {field}");
    }
    assert_eq!(rows[0]["source"], "manual");

    // B's node converges with A on its own.
    let node_b = serve_node(&b, 300);
    let (ok, _, err) = run(&a, &["mesh", "rename", "alpha"]);
    assert!(ok, "{err}");
    wait_for(
        20,
        || devices(&b).iter().any(|d| d["name"] == "alpha"),
        "B to see A's new name",
    );

    // status --json: the node, peers with their device names, lag.
    let st = json(&b, &["mesh", "status"]);
    assert_eq!(st["initialized"], true);
    let node = &st["node"];
    assert_eq!(node["running"], true);
    assert_eq!(node["interval_ms"], 300);
    assert_eq!(node["listen"][0], node_b.addr.as_str());
    assert_eq!(node["advertised"][0], node_b.addr.as_str());
    assert!(node["pid"].as_u64().unwrap() > 0);
    assert!(node["rounds"].as_u64().unwrap() >= 1);
    for field in [
        "started_at",
        "last_round_at",
        "discovery",
        "hooks",
        "active_sessions",
    ] {
        assert!(node.get(field).is_some(), "node lacks {field}");
    }
    let peer = st["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["addr"] == node_a.addr.as_str())
        .unwrap()
        .clone();
    assert_eq!(peer["device_name"], "alpha");
    assert!(peer["last_success_at"].is_string());
    assert_eq!(peer["failures"], 0);
    let lag = st["lag"].as_array().unwrap();
    let la = lag.iter().find(|l| l["device_name"] == "alpha").unwrap();
    for field in [
        "at",
        "completed",
        "at_hello",
        "peer_behind",
        "peer_ahead",
        "peer_behind_now",
        "digest_mismatches",
    ] {
        assert!(la.get(field).is_some(), "lag lacks {field}");
    }
    for field in [
        "clock_skew",
        "rejected_items",
        "fork_evidence",
        "repairs_changed",
        "rollback_hold",
        "address_changes",
    ] {
        assert!(st.get(field).is_some(), "status lacks {field}");
    }
    let (_, text, _) = run(&b, &["mesh", "status"]);
    assert!(text.contains("Node:         running"), "{text}");
    assert!(text.contains("Lag at the last exchange"), "{text}");
    assert!(!has_hex64(&serde_json::to_string(&st).unwrap()));
    assert!(!has_hex64(&text));

    // doctor --json.
    let d = json(&b, &["mesh", "doctor"]);
    assert_eq!(d["initialized"], true);
    let checks: Vec<&str> = d["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["check"].as_str().unwrap())
        .collect();
    for c in [
        "schema", "keys", "marker", "items", "views", "node", "listener", "peers",
    ] {
        assert!(checks.contains(&c), "doctor lacks {c}: {checks:?}");
    }
    assert!(
        d["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["severity"] != "problem"),
        "{d}"
    );
    assert!(matches!(
        d["worst"].as_str(),
        Some("ok" | "info" | "warning")
    ));
    let (_, text, _) = run(&b, &["mesh", "doctor"]);
    assert!(text.contains("[ok     ] node:"), "{text}");

    // replicate goes through the running node.
    let r = json(&b, &["mesh", "replicate"]);
    assert_eq!(r["via_node"], true);
    assert!(r["exchanges"][0]["error"].is_null(), "{r}");

    // stop, through the control socket.
    let stopped = json(&b, &["mesh", "stop"]);
    assert_eq!(stopped["stopped"], true);
    let mut node_b = node_b;
    assert!(node_b.child.wait().unwrap().success());
    assert_eq!(json(&b, &["mesh", "status"])["node"]["running"], false);
    assert_eq!(json(&b, &["mesh", "stop"])["stopped"], false);
    // With no node, replicate runs one exchange itself.
    let r = json(&b, &["mesh", "replicate"]);
    assert_eq!(r["via_node"], false);
    assert!(r["exchanges"][0]["error"].is_null(), "{r}");

    let removed = json(&b, &["mesh", "peer", "remove", &node_a.addr]);
    assert_eq!(removed["removed"], true);
    assert_eq!(removed["source"], "manual");
    drop(node_a);
}

#[test]
fn serve_refuses_a_second_node_and_a_too_short_interval() {
    let a = TestVault::new();
    run(&a, &["mesh", "init", "--name", "dev-a"]);
    let _node = serve_node(&a, 1_000);
    let (ok, _, err) = run(&a, &["mesh", "serve", "--listen", "127.0.0.1:0"]);
    assert!(!ok);
    assert!(err.contains("already running"), "{err}");
    let b = TestVault::new();
    run(&b, &["mesh", "init", "--name", "dev-b"]);
    let out = b
        .raw()
        .args([
            "mesh",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--interval",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("at least 5 seconds"));
}

/// Seed a gateway daily row for local project `name` (the gateway writer's
/// own path is covered by crates/gateway/tests/mesh_publish_e2e.rs).
fn seed_usage(tv: &TestVault, name: &str, requests: i64, unpriced: i64, cost: i64) {
    let conn = tv.conn();
    let id: String = conn
        .query_row("SELECT id FROM projects WHERE name = ?1", [name], |r| {
            r.get(0)
        })
        .unwrap();
    let day = api_tracker_core::mesh::kinds::Day::from_unix_ms(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    )
    .to_string();
    conn.execute(
        "INSERT INTO gateway_usage_daily (day, provider_id, project_id, model, request_count,
             usage_event_count, input_tokens, output_tokens, estimated_cost_micros, updated_at,
             unpriced_requests, unextracted_requests, split_known)
         VALUES (?1, 'openai', ?2, 'gpt-x', ?3, ?3, 10, 5, ?4, 'x', ?5, 0, 1)",
        rusqlite::params![day, id, requests, cost, unpriced],
    )
    .unwrap();
}

#[test]
fn share_bind_and_read_usage_across_two_devices_from_the_cli() {
    let a = TestVault::new();
    run(&a, &["mesh", "init", "--name", "dev-a"]);
    let (ok, _, err) = run(&a, &["project", "create", "app"]);
    assert!(ok, "{err}");
    let node_a = serve(&a);
    let inv = json(&a, &["mesh", "invite", "--addr", &node_a.addr]);
    let b = TestVault::new();
    run(
        &b,
        &[
            "mesh",
            "join",
            inv["invite"].as_str().unwrap(),
            "--name",
            "dev-b",
        ],
    );
    let (ok, _, err) = run(&b, &["project", "create", "app"]);
    assert!(ok, "{err}");

    // Share on A.
    let shared = json(&a, &["mesh", "project", "share", "app"]);
    let p = shared["mesh_project_id"].as_str().unwrap().to_owned();
    assert_eq!(shared["bound"], true);
    let (ok, _, err) = run(&a, &["mesh", "project", "share", "app"]);
    assert!(!ok && err.contains("already bound"), "{err}");
    seed_usage(&a, "app", 6, 2, 4_000);

    // B replicates (one-shot; A's serve publishes nothing on its own here,
    // so B pulls what A's `mesh usage` publishes).
    let ua = json(&a, &["mesh", "usage"]);
    assert_eq!(ua["projects"][0]["devices"][0]["totals"]["requests"], 6);
    let r = json(&b, &["mesh", "replicate"]);
    assert!(r["exchanges"][0]["error"].is_null(), "{r}");
    // Not bound on B until B binds it.
    let list = json(&b, &["mesh", "project", "list"]);
    assert_eq!(list[0]["mesh_project_id"], p.as_str());
    assert!(list[0]["bound_local_project"].is_null());
    let bound = json(&b, &["mesh", "project", "bind", &p[..10], "app"]);
    assert_eq!(bound["bound"], true);

    let u = json(&b, &["mesh", "usage"]);
    let proj = &u["projects"][0];
    let dev_a = proj["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["device_name"] == "dev-a")
        .unwrap();
    assert_eq!(dev_a["totals"]["requests"], 6);
    assert_eq!(dev_a["totals"]["unpriced_requests"], 2);
    assert_eq!(dev_a["totals"]["priced_requests"], 4);
    assert!(dev_a["as_of"].is_string());
    assert_eq!(dev_a["stale"], false);
    assert!(proj["total_label"]
        .as_str()
        .unwrap()
        .starts_with("estimated, gateway-observed"));
    assert!(proj["no_data_from"].as_array().unwrap().len() == 1);
    let (_, text, _) = run(&b, &["mesh", "usage"]);
    assert!(
        text.lines()
            .next()
            .unwrap()
            .contains("never summed with provider-reported cost"),
        "honesty label first: {text}"
    );
    assert!(text.contains("No data from dev-b"), "{text}");
    assert!(!has_hex64(&text));

    // Rename, settings, archive.
    json(&a, &["mesh", "project", "rename", &p, "app-shared"]);
    let s = json(&a, &["mesh", "settings", "list"]);
    assert_eq!(s[0]["name"], "retention.usage_days");
    assert_eq!(s[0]["default"], true);
    json(
        &a,
        &["mesh", "settings", "set", "retention.usage_days", "30"],
    );
    assert_eq!(
        json(&a, &["mesh", "settings", "get", "retention.usage_days"])[0]["value"],
        30
    );
    let (ok, _, err) = run(
        &a,
        &["mesh", "settings", "set", "retention.usage_days", "0"],
    );
    assert!(!ok && err.contains("1 to 3650"), "{err}");
    let st = json(&a, &["mesh", "status"]);
    assert!(st["publish"]["minted"].is_u64(), "{st}");
    // `tethra usage` points at the mesh view, without mixing figures in.
    let (_, _, err) = run(&a, &["usage", "report"]);
    assert!(err.contains("tethra mesh usage"), "{err}");
    let unbound = json(&b, &["mesh", "project", "unbind", "app"]);
    assert_eq!(unbound["unbound"], true);
    drop(node_a);
}
