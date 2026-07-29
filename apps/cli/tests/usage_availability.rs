//! NEW-37, CLI half: `tethra usage report` and `tethra budget show` must
//! never render an absent token count or cost as `0` / `$0.00`.
//!
//! The defect: `print_usage_report` printed `totals.input_tokens` and
//! `format_micros(totals.estimated_cost_micros)` unconditionally, and both
//! come from sums that fold `Option` columns with `unwrap_or(0)`. A month
//! in which no record reported tokens printed "Input tokens:   0" — an
//! assertion of measurement where there was none. Five routable providers
//! declare `usage_shape = ""` and can never report a token count at all, so
//! this was the default reading for them.
//!
//! Everything here drives the REAL binary against a throwaway vault under
//! an isolated data directory. Fake credentials only; nothing is installed.

use assert_cmd::Command;
use predicates::prelude::*;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

use api_tracker_core::usage::{self, Attribution, NewUsageSnapshot};

const MASTER_PW: &str = "test-master-password";
const FAKE_OPENAI: &str = "sk-proj-FAKE0000000000000000000000000000FAKE";

struct TestVault {
    _dir: TempDir,
    data_dir: PathBuf,
}

impl TestVault {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        let v = Self {
            _dir: dir,
            data_dir,
        };
        v.cmd().arg("init").assert().success();
        v
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("tethra").unwrap();
        cmd.env_clear()
            .env("TETHRA_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("TETHRA_PASSWORD", MASTER_PW);
        cmd
    }

    fn conn(&self) -> Connection {
        api_tracker_core::db::open(&self.data_dir.join("vault.db")).unwrap()
    }

    fn add_key(&self, project: &str, name: &str, provider: &str, value: &str) {
        let _ = self.cmd().args(["project", "create", project]).assert();
        self.cmd()
            .args([
                "key",
                "add",
                "--project",
                project,
                "--name",
                name,
                "--provider",
                provider,
                "--environment",
                "production",
                "--value-stdin",
            ])
            .write_stdin(value)
            .assert()
            .success();
    }

    fn project_id(&self, name: &str) -> String {
        self.conn()
            .query_row("SELECT id FROM projects WHERE name = ?1", [name], |r| {
                r.get(0)
            })
            .unwrap()
    }

    /// Insert a snapshot the CLI itself cannot create: `usage record`
    /// requires token counts, but the shape under test is a record that
    /// reported none.
    fn plant(&self, snap: NewUsageSnapshot) {
        usage::record(&self.conn(), &snap).unwrap();
    }

    fn report(&self, provider: &str) -> String {
        let out = self
            .cmd()
            .args(["usage", "report", "--provider", provider])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(out).unwrap()
    }
}

fn now() -> String {
    api_tracker_core::clock::now_rfc3339()
}

/// A record that reported nothing: the shape produced by the five routable
/// providers whose manifests declare `usage_shape = ""`.
fn silent(provider: &str) -> NewUsageSnapshot {
    let n = now();
    let mut s = NewUsageSnapshot::new(provider, &n, &n);
    s.attribution = Attribution::ProviderAccount;
    s
}

/// Every line that could carry a fabricated measurement, so a regression
/// cannot hide in whichever line the test forgot to name.
const MEASUREMENT_LABELS: [&str; 6] = [
    "Requests:",
    "Input tokens:",
    "Output tokens:",
    "Total tokens:",
    "Reported cost:",
    "Estimated cost:",
];

/// Fail if any measurement line renders a bare `0` or `$0.00` while also
/// saying the value was not reported. Used as a guard alongside the
/// specific assertions in each test.
fn assert_no_fabricated_zero(stdout: &str) {
    for line in stdout.lines() {
        let Some(label) = MEASUREMENT_LABELS.iter().find(|l| line.contains(*l)) else {
            continue;
        };
        let value = line.split_once(label).unwrap().1.trim();
        if value.starts_with("not reported") {
            assert!(
                !value.contains("$0.00"),
                "an unreported value rendered a zero dollar amount: {line}"
            );
        }
    }
}

// --- the regression ---------------------------------------------------

/// THE REGRESSION TEST. Reverting `print_usage_report` to unconditional
/// rendering makes this fail: the provider reported nothing, so the totals
/// are `unwrap_or(0)` artefacts and printing them asserts a measurement
/// that was never taken.
#[test]
fn absent_usage_is_never_rendered_as_zero_or_zero_dollars() {
    let v = TestVault::new();
    // Two responses observed; neither carried usage.
    v.plant(silent("cohere"));
    v.plant(silent("cohere"));

    let out = v.report("cohere");

    // The record count IS known — it is the denominator, not a measurement
    // that was absent.
    assert!(out.contains("Snapshots:      2"), "output was:\n{out}");

    // None of these may render the coalesced zero.
    for forbidden in [
        "Requests:       0",
        "Input tokens:   0",
        "Output tokens:  0",
        "Total tokens:   0",
        "Reported cost:  $0.00",
        "Estimated cost: $0.00",
    ] {
        assert!(
            !out.contains(forbidden),
            "fabricated a zero: '{forbidden}' appeared in:\n{out}"
        );
    }

    // And each says what is actually true.
    assert!(
        out.contains("Input tokens:   not reported — none of the 2 usage record(s) carried an input token count"),
        "output was:\n{out}"
    );
    assert!(
        out.contains("Total tokens:   not reported — none of the 2 usage record(s)"),
        "output was:\n{out}"
    );
    assert!(
        out.contains("Estimated cost: not reported — none of the 2 usage record(s) carried a local cost estimate"),
        "output was:\n{out}"
    );
    assert!(
        out.contains("Reported cost:  not reported"),
        "output was:\n{out}"
    );
    assert_no_fabricated_zero(&out);
}

// --- the coverage cases -----------------------------------------------

#[test]
fn all_records_known_renders_the_numbers_plainly() {
    let v = TestVault::new();
    v.add_key("app", "key", "openai", FAKE_OPENAI);
    v.cmd()
        .args([
            "usage",
            "record",
            "--credential",
            "app/key",
            "--model",
            "gpt-4o",
            "--input-tokens",
            "1000000",
            "--output-tokens",
            "1000000",
        ])
        .assert()
        .success();

    let out = v.report("openai");
    // A complete total stands alone: no floor qualifier, no caveat.
    assert!(out.contains("Input tokens:   1000000\n"), "output:\n{out}");
    assert!(out.contains("Total tokens:   2000000\n"), "output:\n{out}");
    assert!(
        out.contains("Estimated cost: $12.50 (estimated locally"),
        "output:\n{out}"
    );
    assert!(
        !out.contains("Partial token data"),
        "nothing is partial here:\n{out}"
    );
    assert_no_fabricated_zero(&out);
}

#[test]
fn some_records_unknown_renders_a_labelled_floor() {
    let v = TestVault::new();
    v.add_key("app", "key", "openai", FAKE_OPENAI);
    v.cmd()
        .args([
            "usage",
            "record",
            "--credential",
            "app/key",
            "--model",
            "gpt-4o",
            "--input-tokens",
            "1000000",
            "--output-tokens",
            "1000000",
        ])
        .assert()
        .success();
    // Two more observed responses that carried no usage at all.
    v.plant(silent("openai"));
    v.plant(silent("openai"));

    let out = v.report("openai");
    assert!(
        out.contains(
            "Input tokens:   1000000 — Partial token data: 1 of 3 usage record(s) carried an \
             input token count, and the rest are NOT counted as zero"
        ),
        "output:\n{out}"
    );
    assert!(
        out.contains(
            "Estimated cost: $12.50 — Partial cost data: 1 of 3 usage record(s) carried a local \
             cost estimate"
        ),
        "output:\n{out}"
    );
    assert_no_fabricated_zero(&out);
}

#[test]
fn a_genuinely_measured_zero_is_still_printed_as_zero() {
    let v = TestVault::new();
    v.add_key("app", "key", "openai", FAKE_OPENAI);
    // A real, priced request that consumed nothing. Suppressing this would
    // be a different lie: the measurement exists and its value is 0.
    v.cmd()
        .args([
            "usage",
            "record",
            "--credential",
            "app/key",
            "--model",
            "gpt-4o",
            "--input-tokens",
            "0",
            "--output-tokens",
            "0",
        ])
        .assert()
        .success();

    let out = v.report("openai");
    assert!(out.contains("Input tokens:   0\n"), "output:\n{out}");
    assert!(out.contains("Total tokens:   0\n"), "output:\n{out}");
    assert!(
        out.contains("Estimated cost: $0.00 (estimated locally"),
        "a derived zero from a known-zero token count is real:\n{out}"
    );
}

#[test]
fn a_provider_metered_in_other_units_says_so_instead_of_zero_tokens() {
    let v = TestVault::new();
    for _ in 0..2 {
        let mut s = silent("supabase");
        s.quantity = Some(120.0);
        s.unit = Some("requests".into());
        v.plant(s);
    }

    let out = v.report("supabase");
    assert!(
        out.contains("Total tokens:   not reported by this source — these 2 record(s) are metered in requests, not tokens"),
        "output:\n{out}"
    );
    assert!(!out.contains("Total tokens:   0"), "output:\n{out}");
    // The per-record table shows the provider's own unit verbatim.
    assert!(out.contains("120 requests"), "output:\n{out}");
    assert_no_fabricated_zero(&out);
}

#[test]
fn partial_token_fields_are_reported_per_field() {
    let v = TestVault::new();
    // A response that carried prompt tokens but no completion tokens.
    let mut only_input = silent("google-gemini");
    only_input.input_tokens = Some(900);
    v.plant(only_input);

    let out = v.report("google-gemini");
    assert!(out.contains("Input tokens:   900\n"), "output:\n{out}");
    assert!(
        out.contains("Output tokens:  not reported — none of the 1 usage record(s) carried an output token count"),
        "output:\n{out}"
    );
    assert!(!out.contains("Output tokens:  0"), "output:\n{out}");
    assert_no_fabricated_zero(&out);
}

#[test]
fn per_record_table_cells_say_not_reported_instead_of_going_blank() {
    let v = TestVault::new();
    v.plant(silent("replicate"));

    let out = v.report("replicate");
    // A blank cell reads as "nothing was used", which is the same
    // fabrication as a zero.
    let row = out
        .lines()
        .find(|l| l.contains("provider_sync"))
        .unwrap_or_else(|| panic!("no record row in:\n{out}"));
    assert_eq!(
        row.matches("not reported").count(),
        3,
        "usage, reported cost and estimated cost must each say so: {row}"
    );
    assert!(!row.contains("$0.00"), "row was: {row}");
}

#[test]
fn an_empty_window_reports_nothing_in_scope_rather_than_zero() {
    let v = TestVault::new();
    let out = v.report("openai");
    assert!(out.contains("Snapshots:      0"), "output:\n{out}");
    assert!(
        out.contains("Total tokens:   not reported — no usage record(s) in this window"),
        "output:\n{out}"
    );
    assert!(!out.contains("Total tokens:   0"), "output:\n{out}");
    assert!(!out.contains("Estimated cost: $0.00"), "output:\n{out}");
}

// --- JSON -------------------------------------------------------------

#[test]
fn json_gains_fields_without_repurposing_the_existing_ones() {
    let v = TestVault::new();
    v.add_key("app", "key", "openai", FAKE_OPENAI);
    v.cmd()
        .args([
            "usage",
            "record",
            "--credential",
            "app/key",
            "--model",
            "gpt-4o",
            "--input-tokens",
            "1000000",
            "--output-tokens",
            "1000000",
        ])
        .assert()
        .success();
    v.plant(silent("openai"));

    let out = v
        .cmd()
        .args(["--json", "usage", "report", "--provider", "openai"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();

    // Existing keys keep their existing meaning.
    let totals = &doc["totals"];
    assert_eq!(totals["snapshots"], 2);
    assert_eq!(totals["input_tokens"], 1_000_000);
    assert_eq!(totals["estimated_cost_micros"], 12_500_000);
    assert!(doc["records"].is_array());

    // New keys answer "how many records did that fold?".
    assert_eq!(totals["input_token_rows"], 1);
    assert_eq!(totals["rows_without_input_tokens"], 1);
    assert_eq!(totals["estimated_cost_rows"], 1);
    assert_eq!(totals["rows_without_estimated_cost"], 1);
    assert_eq!(doc["availability"]["input_tokens"]["kind"], "partial");
    assert_eq!(doc["availability"]["input_tokens"]["covered"], 1);
    assert_eq!(doc["availability"]["input_tokens"]["total"], 2);
    assert_eq!(doc["availability"]["reported_cost"]["kind"], "unknown");
}

// --- budgets ----------------------------------------------------------

#[test]
fn budget_over_complete_data_reports_under_budget() {
    let v = TestVault::new();
    v.add_key("app", "key", "openai", FAKE_OPENAI);
    v.cmd()
        .args(["budget", "set", "--project", "app", "--amount", "100.00"])
        .assert()
        .success();
    v.cmd()
        .args([
            "usage",
            "record",
            "--credential",
            "app/key",
            "--model",
            "gpt-4o",
            "--input-tokens",
            "1000000",
            "--output-tokens",
            "1000000",
        ])
        .assert()
        .success();

    v.cmd()
        .args(["budget", "show", "--project", "app"])
        .assert()
        .success()
        .stdout(predicate::str::contains("STATUS: under budget"))
        .stdout(predicate::str::contains("1 of 1 usage record(s) costed"))
        .stdout(predicate::str::contains("Used:          $12.50 ("));
}

/// MUTATION CONTROL for the budget change. With the three-valued verdict
/// reverted, this prints "under budget" over data that cannot support the
/// claim, and the test fails.
#[test]
fn budget_over_partial_data_refuses_to_claim_under_budget() {
    let v = TestVault::new();
    v.add_key("app", "key", "openai", FAKE_OPENAI);
    v.cmd()
        .args(["budget", "set", "--project", "app", "--amount", "100.00"])
        .assert()
        .success();
    v.cmd()
        .args([
            "usage",
            "record",
            "--credential",
            "app/key",
            "--model",
            "gpt-4o",
            "--input-tokens",
            "1000000",
            "--output-tokens",
            "1000000",
        ])
        .assert()
        .success();

    // Three more records attributed to the same project whose cost never
    // arrived. Their spend is unknown, so the $12.50 floor proves nothing.
    let project_id = v.project_id("app");
    for _ in 0..3 {
        let mut s = silent("openai");
        s.project_id = Some(project_id.clone());
        s.attribution = Attribution::LocalProject;
        v.plant(s);
    }

    v.cmd()
        .args(["budget", "show", "--project", "app"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "STATUS: CANNOT EVALUATE — usage data is incomplete",
        ))
        .stdout(predicate::str::contains("STATUS: under budget").not())
        .stdout(predicate::str::contains("Used:          at least $12.50"))
        .stdout(predicate::str::contains(
            "only 1 of 4 usage record(s) carried a locally estimated cost",
        ))
        .stdout(predicate::str::contains("NOT counted as zero"));
}

#[test]
fn budget_over_partial_data_still_proves_an_overrun_when_the_floor_exceeds_it() {
    let v = TestVault::new();
    v.add_key("app", "key", "openai", FAKE_OPENAI);
    v.cmd()
        .args(["budget", "set", "--project", "app", "--amount", "5.00"])
        .assert()
        .success();
    v.cmd()
        .args([
            "usage",
            "record",
            "--credential",
            "app/key",
            "--model",
            "gpt-4o",
            "--input-tokens",
            "1000000",
            "--output-tokens",
            "1000000",
        ])
        .assert()
        .success();
    let project_id = v.project_id("app");
    let mut s = silent("openai");
    s.project_id = Some(project_id);
    s.attribution = Attribution::LocalProject;
    v.plant(s);

    // A floor above the budget proves the overrun — more data could only
    // raise it — so incompleteness must not soften the verdict.
    v.cmd()
        .args(["budget", "show", "--project", "app"])
        .assert()
        .success()
        .stdout(predicate::str::contains("STATUS: OVER BUDGET"))
        .stdout(predicate::str::contains("Used:          at least $12.50"));
}
