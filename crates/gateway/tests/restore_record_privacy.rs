//! RA-006 regression suite: a recorded `.env` prior value must never be
//! readable from disk.
//!
//! # What the audited head did
//!
//! `prior_value_is_recordable` decided, from a value's *shape*, whether it
//! was safe to write into `gateway_project_links.prior_env_json` — a plain
//! `TEXT` column of a SQLite file opened with no `PRAGMA key`. The re-audit
//! showed it admitting values the codebase's own `looks_like_key_material`
//! flagged as key material, including a JWT of exactly the shape
//! `SUPABASE_SERVICE_ROLE_KEY` uses. It recovered a canary from raw
//! `vault.db` at byte offset 527996.
//!
//! # What is asserted here
//!
//! Not "the predicate now rejects these shapes" — that would be the same
//! test one rung higher, and the next unusual shape would defeat it again.
//! Instead: for each of a set of deliberately awkward secrets, the canary
//! does not appear **anywhere on disk** — main database, WAL, and SHM — and
//! undo still restores the value byte-for-byte.
//!
//! The negative control at the bottom proves the sweep can actually find a
//! planted needle, so a pass means the sweep looked rather than that it was
//! broken.

use api_tracker_core::db;
use api_tracker_core::envrestore::RestoreCrypto;
use api_tracker_core::secret::SecretBytes;
use api_tracker_gateway::envlink::{self, LinkRequest};
use api_tracker_gateway::{routes, store};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

fn restore_crypto() -> RestoreCrypto {
    RestoreCrypto::new(
        "vault-test-0001".to_string(),
        SecretBytes::new(vec![0x2au8; 32]),
    )
}

fn migrated(path: &Path) -> Connection {
    let mut conn = db::open(path).unwrap();
    db::migrate(&mut conn).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('vault_id', 'vault-test-0001')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO projects (id, name, description, notes, environments, archived,
             created_at, updated_at, wrapped_project_key, key_wrap_mode)
         VALUES ('p1', 'app', '', '', 'development', 0,
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', x'00', 'vault')",
        [],
    )
    .unwrap();
    conn
}

fn linkable(dir: &Path) -> Connection {
    let conn = migrated(&dir.join("vault.db"));
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    let mut config = store::load_config(&conn).unwrap();
    config.port = Some(49723);
    store::save_config(&conn, &config).unwrap();
    conn
}

fn request(env_file: &Path, dir: &Path, var: Option<&str>) -> LinkRequest {
    LinkRequest {
        project_id: "p1".into(),
        project_name: "app".into(),
        route_prefix: "openai".into(),
        project_dir: Some(dir.to_path_buf()),
        files: vec![env_file.to_path_buf()],
        var_override: var.map(str::to_string),
    }
}

/// Every file the database can leave a copy of a written value in.
fn persistence_surfaces(dir: &Path) -> Vec<PathBuf> {
    let db = dir.join("vault.db");
    vec![
        db.clone(),
        PathBuf::from(format!("{}-wal", db.display())),
        PathBuf::from(format!("{}-shm", db.display())),
    ]
}

/// Search every surface for `needle`, returning the ones that contain it.
///
/// Reads raw BYTES, not rows: a value can survive in a freed page or an
/// uncheckpointed WAL frame long after the row that held it is gone, and
/// that is exactly how the audit recovered its canary.
fn surfaces_containing(dir: &Path, needle: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for path in persistence_surfaces(dir) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
            hits.push(path.display().to_string());
        }
    }
    hits
}

/// Each case is a real-world secret shape, chosen because the audited head's
/// predicate admitted it or because it is a credential the catalog can
/// actually encounter.
struct Case {
    what: &'static str,
    var: &'static str,
    value: &'static str,
}

const CASES: &[Case] = &[
    Case {
        what: "an API key",
        var: "OPENAI_API_KEY",
        value: "sk-proj-CANARYaaa000.xyz789CANARY01",
    },
    Case {
        what: "a database password",
        var: "DB_PASSWORD",
        value: "admin:CANARYbbbS3cr3tPassw0rd",
    },
    Case {
        what: "a Supabase service-role JWT (an RLS-bypassing admin credential)",
        var: "SUPABASE_SERVICE_ROLE_KEY",
        value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJDQU5BUlljY2MifQ.dQw4w9WgXcQCANARY",
    },
    Case {
        what: "a connection string",
        var: "DATABASE_URL",
        value: "postgres://user:CANARYddd@db.internal:5432/app",
    },
    Case {
        what: "an authorization value",
        var: "AUTH_HEADER",
        value: "Bearer CANARYeee0123456789abcdef",
    },
    Case {
        what: "a private URL carrying credentials in its path",
        var: "OPENAI_BASE_URL",
        value: "https://llm.corp.example/CANARYfff45b30d6/v1",
    },
    Case {
        what: "an AWS-shaped secret whose slashes defeat entropy scoring",
        var: "AWS_SECRET_ACCESS_KEY",
        value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARYggg",
    },
    Case {
        what: "a generic high-entropy value",
        var: "SESSION_SECRET",
        value: "CANARYhhh7f3a9c2e5b18d04a6f2c9e13",
    },
    Case {
        what: "a secret under a misleading variable name",
        var: "OPENAI_BASE_URL",
        value: "CANARYiii-not-a-url-at-all-but-a-key",
    },
    Case {
        what: "a short value the placeholder floor would have waved through",
        var: "API_TOKEN",
        value: "CANARYjjj",
    },
];

/// The headline property, once per shape.
#[test]
fn no_recorded_prior_value_is_readable_on_disk() {
    for case in CASES {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join(".env");
        std::fs::write(&env, format!("{}={}\n", case.var, case.value)).unwrap();
        let conn = linkable(dir.path());
        let var_override = (case.var != "OPENAI_BASE_URL").then_some(case.var);
        let req = request(&env, dir.path(), var_override);

        let plan = envlink::plan_link(&conn, &req).unwrap();
        // The consent diff masks removed values EXCEPT for a declared
        // base-URL variable, where showing the exact value being replaced is
        // the point of the screen (ADR 0019 D9). That is a deliberate
        // on-screen disclosure of the user's own file to the user, and it is
        // never persisted — `FilePlan.diff` crosses IPC and is rendered.
        // This suite is about what survives on DISK, so the diff is only
        // checked where masking IS the policy.
        if case.var != "OPENAI_BASE_URL" {
            assert!(
                !plan.files[0].diff.contains("CANARY"),
                "{}: the consent diff must not print the value: {}",
                case.what,
                plan.files[0].diff
            );
        }
        envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap();

        // Force everything out of memory and into the files.
        db::checkpoint_truncate(&conn);

        let needle = case
            .value
            .split(|c: char| !c.is_ascii_alphanumeric())
            .find(|s| s.starts_with("CANARY"))
            .unwrap_or(case.value);
        let hits = surfaces_containing(dir.path(), needle);
        assert!(
            hits.is_empty(),
            "{}: the recorded prior value is READABLE ON DISK in {hits:?} \
             (needle {needle:?})",
            case.what
        );

        // And the capability the encryption buys: undo still works.
        envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
        let after = std::fs::read_to_string(&env).unwrap();
        assert!(
            after.contains(case.value),
            "{}: a sealed prior value must restore byte-for-byte, got: {after}",
            case.what
        );
    }
}

/// Without the control, `no_recorded_prior_value_is_readable_on_disk` could
/// pass because the sweep never reads anything.
#[test]
fn control_the_disk_sweep_can_find_a_planted_needle() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('canary-probe', ?1)",
        ["CANARYcontrol0123456789"],
    )
    .unwrap();
    db::checkpoint_truncate(&conn);

    let hits = surfaces_containing(dir.path(), "CANARYcontrol0123456789");
    assert!(
        !hits.is_empty(),
        "MUTATION CONTROL FAILED: the sweep cannot find a value that IS on \
         disk, so every absence assertion in this file is vacuous"
    );
}

/// The value must not survive in a freed page after the link row is deleted
/// either — `secure_delete` is on, and this is what proves it for this column.
#[test]
fn unlinking_leaves_no_copy_behind() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(
        &env,
        "OPENAI_BASE_URL=https://corp.example/CANARYresidue999/v1\n",
    )
    .unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, dir.path(), None);
    let plan = envlink::plan_link(&conn, &req).unwrap();
    envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap();
    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    db::checkpoint_truncate(&conn);

    let hits = surfaces_containing(dir.path(), "CANARYresidue999");
    assert!(
        hits.is_empty(),
        "a residue of the restored value survives in {hits:?}"
    );
    assert!(
        std::fs::read_to_string(&env)
            .unwrap()
            .contains("CANARYresidue999"),
        "and the value must be back in the user's file"
    );
}

/// With no key, the value is withheld — never written in the clear.
#[test]
fn without_a_key_the_value_is_withheld_not_written_in_the_clear() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(
        &env,
        "OPENAI_BASE_URL=https://corp.example/CANARYnokey777/v1\n",
    )
    .unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, dir.path(), None);
    let plan = envlink::plan_link(&conn, &req).unwrap();
    envlink::apply_link(&conn, None, &req, &plan).unwrap();
    db::checkpoint_truncate(&conn);

    let hits = surfaces_containing(dir.path(), "CANARYnokey777");
    assert!(
        hits.is_empty(),
        "with no key the value must be WITHHELD, not written in the clear: {hits:?}"
    );
    let stored: String = conn
        .query_row(
            "SELECT prior_env_json FROM gateway_project_links WHERE project_id = 'p1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        stored.contains("\"prior_withheld\":true"),
        "and the user must be able to see that automatic restore was lost: {stored}"
    );
}

/// A ciphertext is bound to its (link, file, variable): moving it must fail
/// to open rather than restore the wrong secret into the wrong place.
#[test]
fn a_sealed_value_moved_to_another_variable_does_not_open() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(
        &env,
        "OPENAI_BASE_URL=https://corp.example/CANARYbound555/v1\n",
    )
    .unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, dir.path(), None);
    let plan = envlink::plan_link(&conn, &req).unwrap();
    envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap();

    // Rename the variable the ciphertext belongs to.
    conn.execute(
        "UPDATE gateway_project_links
         SET prior_env_json = replace(prior_env_json, 'OPENAI_BASE_URL', 'OPENAI_API_BASE')
         WHERE project_id = 'p1'",
        [],
    )
    .unwrap();

    let result = envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai");
    assert!(
        result.is_err(),
        "a transplanted ciphertext must fail to open, not restore somewhere else"
    );
    assert!(
        std::fs::read_to_string(&env).unwrap().contains("127.0.0.1"),
        "and the file must be left for a human to sort out, not half-restored"
    );
}
