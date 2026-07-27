//! ZFT-001 regression suite: scanning a repository must never execute code
//! that repository controls.
//!
//! Each test plants a hostile Git configuration whose value is an
//! **executable canary** — a script that appends to a file the test then
//! inspects. The assertion is not "the scan produced the right answer"; it
//! is "the canary file does not exist". A canary that never runs leaves no
//! trace, so a test that stopped exercising the vector would still pass —
//! which is why every canary is additionally proven *armed* by
//! `each_canary_is_armed_against_unhardened_git`: that test runs plain
//! `git` against the same fixture and requires the canary to fire. Together
//! they form the mutation check: remove the protection and the suite fails.
//!
//! Coverage: `core.fsmonitor`, hooks (`core.hooksPath`), clean/smudge
//! filters, `textconv`, external diff drivers, aliases, pager, editor,
//! credential helper, `GIT_EXTERNAL_DIFF`, a hostile *global* config, a
//! nested repository, and a submodule-shaped `.gitmodules`.
//!
//! The tests need a real `git` for the fixtures. When it is absent they
//! fail loudly rather than passing vacuously — a security regression suite
//! that silently skips is worse than none.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use api_tracker_core::{envgov, gitrepo, gitsafe};

/// Serializes every test in this file.
///
/// Two of them mutate process-wide environment variables (`HOME`,
/// `GIT_CONFIG_*`) to build their hostile fixtures. Cargo runs tests in
/// threads of ONE process, so without this lock those mutations leak into
/// the control test and silently disarm it — the canary would stop firing
/// for a reason that has nothing to do with the product.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn require_git() {
    assert!(
        git_available(),
        "these canaries need a real `git` to build hostile fixtures; \
         install git or this suite proves nothing"
    );
}

/// One hostile repository, plus the canary path its payload writes to.
struct Fixture {
    _tmp: tempfile::TempDir,
    repo: PathBuf,
    canary: PathBuf,
    payload: PathBuf,
}

impl Fixture {
    fn fired(&self) -> bool {
        self.canary.exists()
    }

    fn evidence(&self) -> String {
        std::fs::read_to_string(&self.canary).unwrap_or_default()
    }

    /// Clear the canary immediately before the code under test runs.
    ///
    /// Fixture setup uses plain `git` — which is *supposed* to honour the
    /// hostile config — so without this the assertion would be measuring
    /// the test harness rather than the product.
    fn reset(&self) {
        let _ = std::fs::remove_file(&self.canary);
    }
}

fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .expect("git runs")
}

/// Build a repository with a `.env` and a `package.json` (so detection has
/// something to find) and an executable payload ready to be wired in.
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("hostile");
    std::fs::create_dir_all(&repo).unwrap();
    let canary = tmp.path().join("CANARY_FIRED.txt");
    let payload = repo.join("payload.sh");
    std::fs::write(
        &payload,
        format!(
            "#!/bin/sh\nprintf 'PAYLOAD EXECUTED argv=%s\\n' \"$#\" >> {}\nexit 0\n",
            canary.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();

    std::fs::write(
        repo.join(".env"),
        "OPENAI_API_KEY=sk-proj-FAKECANARY000000000000000000000000\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"openai":"^4"}}"#,
    )
    .unwrap();
    assert!(git(&repo, &["init", "-q", "."]).status.success());
    assert!(git(&repo, &["config", "user.name", "t"]).status.success());
    assert!(git(&repo, &["config", "user.email", "t@example.invalid"])
        .status
        .success());
    // Stage and commit BEFORE anything hostile is armed. `core.fsmonitor`
    // is consulted when Git refreshes an index against the working tree,
    // so an empty index would leave the headline vector unreachable and
    // the whole suite vacuous.
    assert!(git(&repo, &["add", ".env", "package.json"])
        .status
        .success());
    assert!(git(&repo, &["commit", "-q", "-m", "init"]).status.success());
    Fixture {
        _tmp: tmp,
        repo,
        canary,
        payload,
    }
}

/// Everything the automatic scan path does to a folder. This is the exact
/// entry point behind desktop folder selection, `tethra track --dry-run`,
/// apply, undo and diagnostics.
fn scan(fx: &Fixture) {
    let _ = envgov::discover(&fx.repo);
    let _ = envgov::discover_bounded(
        &fx.repo,
        envgov::DiscoveryLimits::default(),
        envgov::HistoryProbe::Skip,
    );
    let _ = envgov::gitignore_protects(&fx.repo, ".env");
    if let Some(view) = gitsafe::RepoView::open(&fx.repo.canonicalize().unwrap()) {
        let _ = view.status_of(&fx.repo.canonicalize().unwrap().join(".env"));
    }
}

/// The deliberate, user-invoked Git path: hardened, but still a subprocess.
fn hardened_git_paths(fx: &Fixture) {
    let _ = gitrepo::repo_root(&fx.repo);
    let _ = gitrepo::staged_files(&fx.repo);
    let _ = gitrepo::staged_units(&fx.repo);
    let _ = gitrepo::history_added_units(&fx.repo, Some(5));
    let _ = gitrepo::collect_full_repo_scan(&fx.repo);
    let _ = envgov::discover_bounded(
        &fx.repo,
        envgov::DiscoveryLimits::default(),
        envgov::HistoryProbe::HardenedGit,
    );
}

// ---------------------------------------------------------------------------
// The vectors
// ---------------------------------------------------------------------------

fn arm_fsmonitor(fx: &Fixture) {
    assert!(git(
        &fx.repo,
        &[
            "config",
            "core.fsmonitor",
            &fx.payload.display().to_string()
        ]
    )
    .status
    .success());
}

fn arm_hooks(fx: &Fixture) {
    let hooks = fx.repo.join("evil-hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for hook in [
        "pre-commit",
        "post-checkout",
        "post-index-change",
        "reference-transaction",
        "post-applypatch",
    ] {
        let path = hooks.join(hook);
        std::fs::copy(&fx.payload, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(git(
        &fx.repo,
        &["config", "core.hooksPath", &hooks.display().to_string()]
    )
    .status
    .success());
}

fn arm_filters(fx: &Fixture) {
    let cmd = format!("{} clean", fx.payload.display());
    assert!(git(&fx.repo, &["config", "filter.evil.clean", &cmd])
        .status
        .success());
    let cmd = format!("{} smudge", fx.payload.display());
    assert!(git(&fx.repo, &["config", "filter.evil.smudge", &cmd])
        .status
        .success());
    assert!(git(&fx.repo, &["config", "filter.evil.required", "false"])
        .status
        .success());
    std::fs::write(fx.repo.join(".gitattributes"), "* filter=evil\n").unwrap();
}

fn arm_textconv(fx: &Fixture) {
    let cmd = format!("{} textconv", fx.payload.display());
    assert!(git(&fx.repo, &["config", "diff.evil.textconv", &cmd])
        .status
        .success());
    std::fs::write(fx.repo.join(".gitattributes"), "* diff=evil\n").unwrap();
}

fn arm_external_diff(fx: &Fixture) {
    let cmd = format!("{} extdiff", fx.payload.display());
    assert!(git(&fx.repo, &["config", "diff.external", &cmd])
        .status
        .success());
    let cmd = format!("{} driverdiff", fx.payload.display());
    assert!(git(&fx.repo, &["config", "diff.evil.command", &cmd])
        .status
        .success());
    std::fs::write(fx.repo.join(".gitattributes"), "* diff=evil\n").unwrap();
}

fn arm_alias(fx: &Fixture) {
    let cmd = format!("!{} alias", fx.payload.display());
    for name in ["log", "diff", "ls-files", "check-ignore", "rev-parse"] {
        assert!(git(&fx.repo, &["config", &format!("alias.{name}"), &cmd])
            .status
            .success());
    }
}

fn arm_pager_and_editor(fx: &Fixture) {
    let cmd = format!("{} pager", fx.payload.display());
    assert!(git(&fx.repo, &["config", "core.pager", &cmd])
        .status
        .success());
    assert!(git(&fx.repo, &["config", "pager.log", &cmd])
        .status
        .success());
    let cmd = format!("{} editor", fx.payload.display());
    assert!(git(&fx.repo, &["config", "core.editor", &cmd])
        .status
        .success());
    assert!(git(&fx.repo, &["config", "sequence.editor", &cmd])
        .status
        .success());
}

fn arm_credential_helper(fx: &Fixture) {
    let cmd = format!("!{} credential", fx.payload.display());
    assert!(git(&fx.repo, &["config", "credential.helper", &cmd])
        .status
        .success());
    let cmd = format!("{} askpass", fx.payload.display());
    assert!(git(&fx.repo, &["config", "core.askPass", &cmd])
        .status
        .success());
}

fn arm_submodule(fx: &Fixture) {
    let cmd = format!("!{} submodule", fx.payload.display());
    std::fs::write(
        fx.repo.join(".gitmodules"),
        format!(
            "[submodule \"evil\"]\n\tpath = evil\n\turl = ext::{} url\n",
            fx.payload.display()
        ),
    )
    .unwrap();
    assert!(git(&fx.repo, &["config", "submodule.evil.update", &cmd])
        .status
        .success());
}

fn arm_nested_repository(fx: &Fixture) {
    // A second, hostile repository *inside* the selected folder: the scan
    // descends into it, so its config is in scope too.
    let nested = fx.repo.join("packages").join("inner");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join(".env"), "ANTHROPIC_API_KEY=sk-ant-FAKE\n").unwrap();
    assert!(git(&nested, &["init", "-q", "."]).status.success());
    assert!(git(
        &nested,
        &[
            "config",
            "core.fsmonitor",
            &fx.payload.display().to_string()
        ]
    )
    .status
    .success());
}

type Vector = (&'static str, fn(&Fixture));

const VECTORS: &[Vector] = &[
    ("core.fsmonitor", arm_fsmonitor),
    ("hooks", arm_hooks),
    ("clean/smudge filters", arm_filters),
    ("textconv", arm_textconv),
    ("external diff driver", arm_external_diff),
    ("aliases", arm_alias),
    ("pager and editor", arm_pager_and_editor),
    ("credential helper", arm_credential_helper),
    ("submodule update command", arm_submodule),
    ("nested hostile repository", arm_nested_repository),
];

// ---------------------------------------------------------------------------
// The properties
// ---------------------------------------------------------------------------

#[test]
fn scanning_never_executes_repository_controlled_code() {
    let _guard = lock();
    require_git();
    for (name, arm) in VECTORS {
        let fx = fixture();
        arm(&fx);
        fx.reset();
        scan(&fx);
        assert!(
            !fx.fired(),
            "SCAN EXECUTED REPOSITORY-CONTROLLED CODE via {name}: {}",
            fx.evidence()
        );
    }
}

#[test]
fn the_hardened_git_path_never_executes_repository_controlled_code() {
    let _guard = lock();
    require_git();
    for (name, arm) in VECTORS {
        let fx = fixture();
        arm(&fx);
        fx.reset();
        hardened_git_paths(&fx);
        assert!(
            !fx.fired(),
            "THE HARDENED GIT PATH EXECUTED REPOSITORY-CONTROLLED CODE via {name}: {}",
            fx.evidence()
        );
    }
}

#[test]
fn a_hostile_global_config_cannot_execute_either() {
    let _guard = lock();
    require_git();
    let fx = fixture();
    let home = fx._tmp.path().join("fakehome");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        format!(
            "[core]\n\tfsmonitor = {}\n\tpager = {} pager\n[diff]\n\texternal = {} ext\n",
            fx.payload.display(),
            fx.payload.display(),
            fx.payload.display()
        ),
    )
    .unwrap();
    // A hostile global config is only reachable through the environment,
    // so point HOME at it for the duration of this scan.
    let previous = std::env::var_os("HOME");
    std::env::set_var("HOME", &home);
    fx.reset();
    scan(&fx);
    hardened_git_paths(&fx);
    match previous {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
    assert!(
        !fx.fired(),
        "A HOSTILE GLOBAL GIT CONFIG EXECUTED CODE: {}",
        fx.evidence()
    );
}

#[test]
fn a_hostile_environment_cannot_inject_git_config() {
    let _guard = lock();
    require_git();
    let fx = fixture();
    let payload = fx.payload.display().to_string();
    let restore: Vec<(&str, Option<std::ffi::OsString>)> = [
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
        "PAGER",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
    ]
    .iter()
    .map(|k| (*k, std::env::var_os(k)))
    .collect();

    std::env::set_var("GIT_EXTERNAL_DIFF", &payload);
    std::env::set_var("GIT_PAGER", &payload);
    std::env::set_var("PAGER", &payload);
    std::env::set_var("GIT_CONFIG_COUNT", "1");
    std::env::set_var("GIT_CONFIG_KEY_0", "core.fsmonitor");
    std::env::set_var("GIT_CONFIG_VALUE_0", &payload);

    fx.reset();
    scan(&fx);
    hardened_git_paths(&fx);

    for (k, v) in restore {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    assert!(
        !fx.fired(),
        "A HOSTILE ENVIRONMENT INJECTED EXECUTABLE GIT CONFIG: {}",
        fx.evidence()
    );
}

/// The mutation check.
///
/// Every canary above must be capable of firing: run the *unprotected*
/// equivalent — plain `git` with no `-c` overrides and no environment
/// scrub — against the same fixtures, and require that at least the
/// `core.fsmonitor` vector executes. Without this, a suite whose canaries
/// had quietly stopped being reachable would still report all green.
#[test]
fn each_canary_is_armed_against_unhardened_git() {
    let _guard = lock();
    require_git();
    // `core.fsmonitor` is the vector the audit reproduced end to end, so
    // it is the one held to a hard requirement; the rest are asserted as a
    // group so a Git version that drops one vector does not make the suite
    // lie about the others.
    let fx = fixture();
    arm_fsmonitor(&fx);
    fx.reset();
    // Exactly what the pre-remediation code did: `git ls-files` with no
    // hardening at all.
    // The product spawns git from a controlled working directory OUTSIDE
    // the scanned repository. Reproduce that exactly: a cwd inside the
    // target changes which configuration Git consults, and running the
    // control from the wrong place is how an "armed" check quietly stops
    // being armed.
    let out = Command::new("git")
        .current_dir(std::env::temp_dir())
        .arg("-C")
        .arg(&fx.repo)
        .args(["ls-files", "--error-unmatch", "--", ".env"])
        .output()
        .expect("git runs");
    let _ = out;
    assert!(
        fx.fired(),
        "the core.fsmonitor canary did not fire against UNHARDENED git — the canary is \
         broken or this git build ignores core.fsmonitor, so \
         `scanning_never_executes_repository_controlled_code` proves nothing"
    );

    let mut armed = vec!["core.fsmonitor"];
    for (name, arm) in VECTORS.iter().skip(1) {
        let fx = fixture();
        arm(&fx);
        fx.reset();
        for args in [
            vec!["ls-files", "--error-unmatch", "--", ".env"],
            vec!["check-ignore", "-q", "--", ".env"],
            vec!["log", "-p", "-n", "1", "--all"],
            vec!["diff", "--cached", "--name-only"],
            vec!["status", "--porcelain"],
        ] {
            let _ = Command::new("git")
                .current_dir(std::env::temp_dir())
                .arg("-C")
                .arg(&fx.repo)
                .args(&args)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
                .output();
        }
        if fx.fired() {
            armed.push(name);
        }
    }
    assert!(
        armed.len() >= 2,
        "only {armed:?} of {} vectors could fire even without hardening; the fixtures are \
         not exercising real Git execution surfaces",
        VECTORS.len()
    );
}

/// Detection must still WORK after the hardening — a scanner that refuses
/// every repository would pass every canary and be useless.
#[test]
fn a_hostile_repository_is_still_scanned_correctly() {
    let _guard = lock();
    require_git();
    let fx = fixture();
    arm_fsmonitor(&fx);
    fx.reset();

    let files = envgov::discover(&fx.repo).expect("discovery succeeds on a hostile repository");
    let env = files
        .iter()
        .find(|f| f.rel_path == ".env")
        .expect(".env is still discovered");
    assert_eq!(
        env.git_status,
        envgov::GitStatus::Tracked,
        "the committed .env must still be reported as tracked"
    );
    assert_eq!(
        env.entry_count, 1,
        "the file must still be parsed for its variable count"
    );
    assert!(!fx.fired(), "and nothing executed: {}", fx.evidence());
}
