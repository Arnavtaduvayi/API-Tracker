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
