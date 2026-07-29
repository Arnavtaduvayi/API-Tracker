//! `ORG-01` / `ZFT-004` regression suite: **repository content is not
//! authorization.**
//!
//! # The original defect
//!
//! A repository containing nothing but a committed `package.json` and a
//! committed `SUPABASE_URL` was enough to make Tethra build a route to a host
//! the *repository* chose and forward the user's API credential to it. ADR
//! 0024 split the two decisions that had been collapsed into one: `--yes`
//! answers "run the setup", never "send my traffic to a host this repository
//! picked".
//!
//! # Why this file exists
//!
//! The refusal branch in `track_cmd.rs` is that fix's *entire* enforcement
//! point, and the independent re-audit found it had no test at all: replacing
//! the refusal with an approval left all 96 CLI tests and every crate green,
//! while the mutated binary reproduced `ZFT-004` verbatim. The library test
//! that reads as if it covers this
//! (`tracking/tests/origin_trust.rs::a_yes_run_cannot_route_to_an_unapproved_repository_origin`)
//! calls `Selections::defaults()` directly and never executes the CLI branch.
//!
//! These tests drive the real binary.
//!
//! # Why every test here stops before `apply`
//!
//! Each fixture declares **only** repository-chosen destinations, so once
//! they are refused nothing remains to configure and `track` exits 2 at
//! "Nothing detected is automatically configurable yet" — which is *before*
//! apply step 1, and therefore before `EnsureService` (step 3) could touch
//! launchd. That is deliberate: `launchctl` operates on `gui/<uid>`, so a
//! redirected `$HOME` does **not** isolate a service install from the
//! developer's real session. The one place a mixed built-in/custom repository
//! is driven all the way through apply is the packaged macOS validation on
//! the disposable CI runner.
//!
//! The `--dry-run` tests cover the mixed case: they show the built-in
//! provider being configured automatically in the same run where the
//! repository-chosen destination is refused.

#![cfg(unix)]

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const MASTER_PW: &str = "test-master-password";
const FAKE_OPENAI_KEY: &str = "sk-proj-FAKE-TEST-KEY-0000000000000001";
const ATTACKER: &str = "attacker-controlled.example.com";

struct TestVault {
    _dir: TempDir,
    data_dir: PathBuf,
}

impl TestVault {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        let tv = TestVault {
            _dir: dir,
            data_dir,
        };
        tv.cmd().arg("init").assert().success();
        tv
    }

    fn home(&self) -> PathBuf {
        self._dir.path().join("home")
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("tethra").unwrap();
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home())
            .env("TETHRA_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("TETHRA_PASSWORD", MASTER_PW);
        c
    }

    fn project_dir(&self, name: &str) -> PathBuf {
        let p = self._dir.path().join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn db(&self) -> Connection {
        Connection::open(self.data_dir.join("vault.db")).unwrap()
    }

    fn count(&self, sql: &str) -> i64 {
        self.db().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    /// The three things that must all still be true after a refusal.
    fn assert_nothing_was_authorized(&self, host: &str) {
        assert_eq!(
            self.count("SELECT COUNT(*) FROM tracking_approved_origins"),
            0,
            "a refused run must not persist an approval record"
        );
        assert_eq!(
            self.count("SELECT COUNT(*) FROM gateway_routes"),
            0,
            "a refused run must not create a route"
        );
        let leaked: i64 = self
            .db()
            .query_row(
                "SELECT COUNT(*) FROM gateway_routes WHERE custom_origin LIKE ?1",
                [format!("%{host}%")],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(leaked, 0, "no route may point at {host}");
        // Nothing may have been written into the launchd directory either —
        // this is the isolation invariant the module docs describe.
        let la = self.home().join("Library/LaunchAgents");
        if la.exists() {
            let entries: Vec<_> = std::fs::read_dir(&la).unwrap().collect();
            assert!(
                entries.is_empty(),
                "a refused run installed a LaunchAgent: {entries:?}"
            );
        }
    }
}

fn write(dir: &Path, files: &[(&str, &str)]) {
    for (rel, content) in files {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }
}

/// The audit's fixture: a committed dependency plus a committed base URL, and
/// nothing else Tethra could configure on its own.
fn one_custom_origin(dir: &Path) {
    write(
        dir,
        &[
            (
                "package.json",
                r#"{"dependencies":{"@supabase/supabase-js":"^2.39.0"}}"#,
            ),
            (
                ".env.development",
                &format!("SUPABASE_URL=https://{ATTACKER}\n"),
            ),
        ],
    );
}

const REFUSAL: &str = "NOT approved: --yes does not approve a project-chosen destination";

// ---------------------------------------------------------------------------
// The blocking property
// ---------------------------------------------------------------------------

/// `tethra track . --yes` must not approve a repository-derived origin.
#[test]
fn a_yes_run_refuses_a_repository_chosen_origin() {
    let tv = TestVault::new();
    let dir = tv.project_dir("one");
    one_custom_origin(&dir);

    let out = tv.cmd().args(["track", "--yes"]).arg(&dir).assert().code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();

    assert!(
        stdout.contains(REFUSAL),
        "the refusal must be stated in product terms:\n{stdout}"
    );
    assert!(
        stdout.contains("--allow-origin"),
        "and it must be actionable — say how to approve it deliberately:\n{stdout}"
    );
    assert!(
        stdout.contains("Nothing detected is automatically configurable yet"),
        "with nothing left to do, the run must say so rather than claim success:\n{stdout}"
    );
    tv.assert_nothing_was_authorized(ATTACKER);
}

/// Several repository-chosen destinations in one repository: every one of
/// them must be refused, not just the first.
#[test]
fn a_yes_run_refuses_several_repository_chosen_origins() {
    let tv = TestVault::new();
    let dir = tv.project_dir("several");
    write(
        &dir,
        &[
            (
                "package.json",
                r#"{"dependencies":{"@supabase/supabase-js":"^2.39.0","openai":"^4.0.0"}}"#,
            ),
            (
                ".env",
                "SUPABASE_URL=https://one.attacker.example.com\n\
                 OPENAI_BASE_URL=https://two.attacker.example.com\n",
            ),
        ],
    );

    let out = tv.cmd().args(["track", "--yes"]).arg(&dir).assert().code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();

    assert_eq!(
        stdout.matches(REFUSAL).count(),
        2,
        "each destination is a separate decision and each must be refused:\n{stdout}"
    );
    for host in ["one.attacker.example.com", "two.attacker.example.com"] {
        assert!(stdout.contains(host), "{host} must be disclosed verbatim");
        tv.assert_nothing_was_authorized(host);
    }
}

/// A repository that dresses a destination of its own choosing up as a
/// **built-in** provider does not get built-in treatment.
///
/// This is the sharpest case: `openai` IS a shipped manifest provider, and a
/// repository declaring `OPENAI_BASE_URL` is asking Tethra to send an OpenAI
/// credential somewhere that is not OpenAI. Declaring the base URL must
/// demote the provider out of the automatic set, not inherit its trust.
#[test]
fn a_repository_cannot_disguise_a_custom_origin_as_a_builtin_provider() {
    let tv = TestVault::new();
    let dir = tv.project_dir("disguise");
    write(
        &dir,
        &[
            (
                "package.json",
                r#"{"dependencies":{"openai":"^4.0.0","dotenv":"^16.0.0"}}"#,
            ),
            (
                ".env",
                &format!(
                    "OPENAI_API_KEY={FAKE_OPENAI_KEY}\nOPENAI_BASE_URL=https://evil.example.com\n"
                ),
            ),
        ],
    );

    let out = tv.cmd().args(["track", "--yes"]).arg(&dir).assert().code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();

    assert!(
        stdout.contains(REFUSAL),
        "a base URL the repository chose is a custom destination however \
         familiar the provider name is:\n{stdout}"
    );
    assert!(
        stdout.contains("evil.example.com"),
        "and the real destination must be shown to the user:\n{stdout}"
    );
    tv.assert_nothing_was_authorized("evil.example.com");
}

/// No terminal and no `--yes` is still a refusal, and a different one — the
/// two paths are separate branches and both must hold.
#[test]
fn a_noninteractive_run_without_yes_also_refuses() {
    let tv = TestVault::new();
    let dir = tv.project_dir("nontty");
    one_custom_origin(&dir);

    // assert_cmd gives the child a pipe, never a tty.
    let out = tv
        .cmd()
        .args(["track"])
        .arg(&dir)
        .write_stdin("y\ny\ny\n")
        .assert()
        .code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();

    assert!(
        stdout.contains("NOT approved: no terminal to ask on"),
        "a piped 'y' is not consent:\n{stdout}"
    );
    tv.assert_nothing_was_authorized(ATTACKER);
}

// ---------------------------------------------------------------------------
// Controls: the refusal is specific, not a blanket failure
// ---------------------------------------------------------------------------

/// `--allow-origin` with the exact origin DOES approve it.
///
/// Without this control every assertion above could be satisfied by a build
/// that refuses everything and can never configure a custom destination at
/// all. `--dry-run` keeps the run away from `apply`; the approval decision
/// itself is made before either branch.
#[test]
fn control_allow_origin_approves_that_exact_destination() {
    let tv = TestVault::new();
    let dir = tv.project_dir("allowed");
    one_custom_origin(&dir);

    let out = tv
        .cmd()
        .args(["track", "--dry-run", "--allow-origin"])
        .arg(format!("https://{ATTACKER}"))
        .arg(&dir)
        .assert();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();

    assert!(
        stdout.contains("approved by --allow-origin"),
        "an explicitly named origin must be accepted:\n{stdout}"
    );
    assert!(
        !stdout.contains(REFUSAL),
        "and must not also be refused:\n{stdout}"
    );
    assert_eq!(
        tv.count("SELECT COUNT(*) FROM tracking_approved_origins"),
        0,
        "a dry run must still persist nothing"
    );
}

/// `--allow-origin` is matched on the CANONICAL origin, so equivalent
/// spellings of the same destination are accepted…
///
/// The canonical form is a bare authority with a case-folded host. Case and
/// an explicit `:443` are the only things normalized away, deliberately: any
/// further loosening is a way for a destination the user never approved to
/// match an approval they did give.
#[test]
fn control_allow_origin_accepts_canonical_variants_of_the_same_origin() {
    for spelling in [
        "https://attacker-controlled.example.com",
        "https://ATTACKER-CONTROLLED.EXAMPLE.COM",
        "https://Attacker-Controlled.Example.Com",
        "https://attacker-controlled.example.com:443",
    ] {
        let tv = TestVault::new();
        let dir = tv.project_dir("canon");
        one_custom_origin(&dir);

        let out = tv
            .cmd()
            .args(["track", "--dry-run", "--allow-origin", spelling])
            .arg(&dir)
            .assert();
        let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
        assert!(
            stdout.contains("approved by --allow-origin"),
            "{spelling} is the same destination and must be accepted:\n{stdout}"
        );
    }
}

/// …and a DIFFERENT destination is not, however similar it looks. A
/// near-miss must not inherit the approval.
///
/// Every value here is a perfectly well-formed origin, so it survives
/// `validate_allow_origins` and reaches the comparison — which is the point:
/// the refusal below is the matcher declining, not the parser.
#[test]
fn a_near_miss_allow_origin_does_not_approve_the_repositorys_choice() {
    for near_miss in [
        "https://attacker-controlled.example.com.evil.test",
        "https://attacker-controlled.example.co",
        "https://attacker-controlled-example.com",
        "https://sub.attacker-controlled.example.com",
        "https://xn--attacker-controlled.example.com",
    ] {
        let tv = TestVault::new();
        let dir = tv.project_dir("nearmiss");
        one_custom_origin(&dir);

        let out = tv
            .cmd()
            .args(["track", "--yes", "--allow-origin", near_miss])
            .arg(&dir)
            .assert()
            .code(2);
        let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
        assert!(
            stdout.contains(REFUSAL),
            "{near_miss} is a different destination and must not approve \
             https://{ATTACKER}:\n{stdout}"
        );
        tv.assert_nothing_was_authorized(ATTACKER);
    }
}

/// A `--allow-origin` the canonicalizer cannot parse is reported, not
/// silently ignored.
///
/// A trailing slash is the obvious way to get this wrong — it is how the
/// destination appears in a browser, and `origin::canonicalize` rejects it
/// because a path is not part of an origin. Before this check the value
/// simply never matched, so the user was told "NOT approved" for the exact
/// destination they had just named on the command line, with nothing
/// anywhere explaining why.
#[test]
fn a_malformed_allow_origin_is_reported_rather_than_silently_ignored() {
    for bad in [
        "https://attacker-controlled.example.com/",
        "https://attacker-controlled.example.com/v1",
        "http://attacker-controlled.example.com",
        "attacker-controlled.example.com",
        "https://user@attacker-controlled.example.com",
        "https://attacker-controlled.example.com:8443",
    ] {
        let tv = TestVault::new();
        let dir = tv.project_dir("badflag");
        one_custom_origin(&dir);

        let out = tv
            .cmd()
            .args(["track", "--dry-run", "--allow-origin", bad])
            .arg(&dir)
            .assert()
            .failure();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.get_output().stdout),
            String::from_utf8_lossy(&out.get_output().stderr)
        );
        assert!(
            combined.contains("--allow-origin"),
            "{bad} must be reported against the flag that carried it:\n{combined}"
        );
        tv.assert_nothing_was_authorized(ATTACKER);
    }
}

/// Mixed repository: the built-in provider is configured automatically in the
/// SAME run where the repository-chosen destination is refused. The refusal
/// must not block the rest of the setup, and the setup must not carry the
/// refusal along with it.
#[test]
fn builtin_providers_proceed_while_a_custom_origin_is_refused() {
    let tv = TestVault::new();
    let dir = tv.project_dir("mixed");
    write(
        &dir,
        &[
            (
                "package.json",
                r#"{"dependencies":{"openai":"^4.0.0","dotenv":"^16.0.0","@supabase/supabase-js":"^2.39.0"}}"#,
            ),
            (
                ".env",
                &format!("OPENAI_API_KEY={FAKE_OPENAI_KEY}\nSUPABASE_URL=https://{ATTACKER}\n"),
            ),
        ],
    );

    let out = tv
        .cmd()
        .args(["track", "--dry-run"])
        .arg(&dir)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();

    assert!(
        stdout.contains("openai"),
        "the built-in provider must still be planned:\n{stdout}"
    );
    assert!(
        stdout.contains("NOT approved"),
        "while the repository-chosen destination is not:\n{stdout}"
    );
    assert!(
        !stdout.contains(FAKE_OPENAI_KEY),
        "and no credential value may ever be printed"
    );
    tv.assert_nothing_was_authorized(ATTACKER);
}

/// A refused run must leave the vault exactly as it found it, so that a later
/// run makes the decision again rather than inheriting a half-made one.
#[test]
fn a_refused_run_creates_no_approval_record_for_a_later_run_to_inherit() {
    let tv = TestVault::new();
    let dir = tv.project_dir("twice");
    one_custom_origin(&dir);

    tv.cmd().args(["track", "--yes"]).arg(&dir).assert().code(2);
    tv.assert_nothing_was_authorized(ATTACKER);

    // Second run: the decision is asked again, from scratch.
    let out = tv.cmd().args(["track", "--yes"]).arg(&dir).assert().code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains(REFUSAL),
        "the second run must refuse exactly as the first did:\n{stdout}"
    );
    tv.assert_nothing_was_authorized(ATTACKER);
}

/// No credential value may reach the disclosure, the refusal, or anything
/// else this path prints.
#[test]
fn no_credential_value_appears_on_the_refusal_path() {
    let tv = TestVault::new();
    let dir = tv.project_dir("secrets");
    write(
        &dir,
        &[
            (
                "package.json",
                r#"{"dependencies":{"@supabase/supabase-js":"^2.39.0"}}"#,
            ),
            (
                ".env",
                &format!(
                    "SUPABASE_URL=https://{ATTACKER}\n\
                     SUPABASE_SERVICE_ROLE_KEY=sb_secret_FAKE0000000000000000000\n"
                ),
            ),
        ],
    );

    let out = tv.cmd().args(["track", "--yes"]).arg(&dir).assert().code(2);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.get_output().stdout),
        String::from_utf8_lossy(&out.get_output().stderr)
    );
    assert!(
        !combined.contains("sb_secret_FAKE0000000000000000000"),
        "a credential value leaked into the refusal output"
    );
    tv.assert_nothing_was_authorized(ATTACKER);
}
