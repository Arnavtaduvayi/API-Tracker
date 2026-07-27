//! GScan-01 / GScan-02 regression suite: git hook protection must be
//! ACTIVE (git actually executes our scan on commit) and TRUTHFUL (status
//! never claims protection that git will not run).
//!
//! Method: each test makes a REAL `git commit` in a disposable repository
//! with a stub `api-tracker` first on PATH. The stub appends its arguments
//! to a marker file, so "the scan ran" is observable and deterministic.
//! No vault, no network, no real credentials.
//!
//! Baseline evidence (`033f747`): install ignored `core.hooksPath`
//! (GScan-01) and force-chain APPENDED our block after foreign hooks, so an
//! early `exit`/`exec` skipped the scan (GScan-02) — see
//! `docs/remediation-phase-2/evidence/gscan_baseline_fail.log.txt`.

#![cfg(unix)]

use api_tracker_core::{gitrepo, hooks};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use tempfile::TempDir;

/// Serializes tests in this file: some set process-wide env vars
/// (GIT_CONFIG_GLOBAL) that the production code's git subprocesses inherit.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q"]);
}

/// Stub scanner binaries that record their invocation and exit per
/// STUB_EXIT (default 0 = scan clean). Installed under BOTH the preferred
/// `tethra` name and the legacy `api-tracker` name — the hook template
/// prefers `tethra` and falls back to `api-tracker`.
fn write_stub(stub_dir: &Path) {
    write_stub_named(stub_dir, &["tethra", "api-tracker"]);
}

fn write_stub_named(stub_dir: &Path, names: &[&str]) {
    std::fs::create_dir_all(stub_dir).unwrap();
    for name in names {
        let stub = stub_dir.join(name);
        std::fs::write(
            &stub,
            "#!/bin/sh\necho \"$@\" >> \"$MARKER\"\nexit ${STUB_EXIT:-0}\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Stage a unique file and run `git commit` with the stub first on PATH.
/// Returns (commit_succeeded, scan_ran).
fn commit_with_stub(repo: &Path, stub_dir: &Path, marker: &Path, stub_exit: i32) -> (bool, bool) {
    let path_env = format!(
        "{}:{}",
        stub_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    commit_with_stub_path(repo, marker, stub_exit, &path_env)
}

/// Like `commit_with_stub`, but with a caller-controlled PATH. Used by the
/// fallback test, which must NOT see a real `tethra` installed on the
/// developer's machine (the hook prefers it over the legacy stub).
fn commit_with_stub_path(
    repo: &Path,
    marker: &Path,
    stub_exit: i32,
    path_env: &str,
) -> (bool, bool) {
    let _ = std::fs::remove_file(marker);
    let name = format!(
        "f-{}.txt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::fs::write(repo.join(&name), "harmless content\n").unwrap();
    git(repo, &["add", "."]);
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=T",
            "commit",
            "-m",
            "test",
        ])
        .env("PATH", path_env)
        .env("MARKER", marker)
        .env("STUB_EXIT", stub_exit.to_string())
        .output()
        .expect("run git commit");
    (out.status.success(), marker.exists())
}

struct Repo {
    _dir: TempDir,
    root: PathBuf,
    stub_dir: PathBuf,
    marker: PathBuf,
}

fn setup(subdir: &str) -> Repo {
    if !gitrepo::git_available() {
        panic!("git required for hook tests");
    }
    let dir = TempDir::new().unwrap();
    let root = dir.path().join(subdir);
    std::fs::create_dir_all(&root).unwrap();
    init_repo(&root);
    let stub_dir = dir.path().join("stub-bin");
    write_stub(&stub_dir);
    let marker = dir.path().join("scan-ran.marker");
    Repo {
        root,
        stub_dir,
        marker,
        _dir: dir,
    }
}

// ---------------------------------------------------------------- GScan-01

#[test]
fn local_hooks_path_install_is_active_and_commit_scans() {
    let _l = lock();
    let r = setup("repo");
    git(&r.root, &["config", "core.hooksPath", ".custom-hooks"]);

    hooks::install(&r.root, false).expect("install");

    let (committed, scan_ran) = commit_with_stub(&r.root, &r.stub_dir, &r.marker, 0);
    assert!(committed, "clean commit must succeed");
    assert!(
        scan_ran,
        "GScan-01: core.hooksPath is set; the installed protection must \
         actually execute on commit"
    );
}

#[test]
fn global_hooks_path_is_detected_and_used() {
    let _l = lock();
    let r = setup("repo");
    let global_hooks = r.root.parent().unwrap().join("global-hooks");
    std::fs::create_dir_all(&global_hooks).unwrap();
    let cfg = r.root.parent().unwrap().join("gitconfig-global");
    std::fs::write(
        &cfg,
        format!("[core]\n\thooksPath = {}\n", global_hooks.display()),
    )
    .unwrap();

    std::env::set_var("GIT_CONFIG_GLOBAL", &cfg);
    let install = hooks::install(&r.root, false);
    let result = install.map(|_| commit_with_stub(&r.root, &r.stub_dir, &r.marker, 0));
    std::env::remove_var("GIT_CONFIG_GLOBAL");

    let (committed, scan_ran) = result.expect("install under global hooksPath");
    assert!(committed, "clean commit must succeed");
    assert!(
        scan_ran,
        "GScan-01: a GLOBAL core.hooksPath must be honoured — protection \
         must execute on commit"
    );
}

// ---------------------------------------------------------------- GScan-02

#[test]
fn force_chain_scans_before_early_exit_foreign_hook() {
    let _l = lock();
    let r = setup("repo");
    let hook = r.root.join(".git/hooks/pre-commit");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    hooks::install(&r.root, true).expect("force chain");

    let (committed, scan_ran) = commit_with_stub(&r.root, &r.stub_dir, &r.marker, 0);
    assert!(committed);
    assert!(
        scan_ran,
        "GScan-02: our scan must run BEFORE a foreign hook can `exit`"
    );
}

#[test]
fn force_chain_scans_before_exec_foreign_hook() {
    let _l = lock();
    let r = setup("repo");
    let hook = r.root.join(".git/hooks/pre-commit");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, "#!/bin/sh\nexec true\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    hooks::install(&r.root, true).expect("force chain");

    let (committed, scan_ran) = commit_with_stub(&r.root, &r.stub_dir, &r.marker, 0);
    assert!(committed);
    assert!(
        scan_ran,
        "GScan-02: our scan must run BEFORE a foreign hook can `exec` away"
    );
}

#[test]
fn chained_scan_blocks_commit_even_with_permissive_foreign_hook() {
    let _l = lock();
    let r = setup("repo");
    let hook = r.root.join(".git/hooks/pre-commit");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    hooks::install(&r.root, true).expect("force chain");

    // The stub reports findings (exit 1): the commit must be blocked even
    // though the foreign hook would have allowed it.
    let (committed, scan_ran) = commit_with_stub(&r.root, &r.stub_dir, &r.marker, 1);
    assert!(scan_ran, "scan must have run");
    assert!(
        !committed,
        "a failing scan must block the commit regardless of the foreign hook"
    );
}

// ------------------------------------------------------- hook managers etc.

#[test]
fn husky_style_hooks_path_chains_and_preserves_foreign_hook() {
    let _l = lock();
    let r = setup("repo");
    git(&r.root, &["config", "core.hooksPath", ".husky"]);
    let husky_dir = r.root.join(".husky");
    std::fs::create_dir_all(&husky_dir).unwrap();
    let hook = husky_dir.join("pre-commit");
    std::fs::write(&hook, "#!/bin/sh\necho husky-ran >> \"$MARKER.husky\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Foreign hook present in the husky dir: refuse without force…
    assert!(hooks::install(&r.root, false).is_err());
    // …and chain with force, into the DIRECTORY GIT USES.
    hooks::install(&r.root, true).expect("force chain into husky dir");

    let (committed, scan_ran) = commit_with_stub(&r.root, &r.stub_dir, &r.marker, 0);
    assert!(committed);
    assert!(scan_ran, "scan must run under a husky-style hooksPath");
    let husky_marker = PathBuf::from(format!("{}.husky", r.marker.display()));
    assert!(
        husky_marker.exists(),
        "the pre-existing husky hook must still run (semantics preserved)"
    );
}

#[test]
fn repeated_install_is_idempotent() {
    let _l = lock();
    let r = setup("repo");
    git(&r.root, &["config", "core.hooksPath", ".custom-hooks"]);
    hooks::install(&r.root, false).expect("first install");
    let hook = r.root.join(".custom-hooks/pre-commit");
    let first = std::fs::read_to_string(&hook).expect("hook written where git looks");
    hooks::install(&r.root, false).expect("second install");
    let second = std::fs::read_to_string(&hook).unwrap();
    assert_eq!(first, second, "repeated install must not grow the hook");
    assert_eq!(
        second.matches("api-tracker scan --staged --hook").count(),
        1,
        "exactly one managed block"
    );
}

#[test]
fn uninstall_restores_the_prior_foreign_hook() {
    let _l = lock();
    let r = setup("repo");
    let hook = r.root.join(".git/hooks/pre-commit");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, "#!/bin/bash\necho keep-me\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    hooks::install(&r.root, true).expect("force chain");
    hooks::remove(&r.root).expect("remove");

    let content = std::fs::read_to_string(&hook).unwrap();
    assert!(
        content.contains("echo keep-me"),
        "foreign hook content restored"
    );
    assert!(!content.contains("api-tracker"), "our block fully removed");
    assert!(
        content
            .lines()
            .next()
            .unwrap_or_default()
            .starts_with("#!/bin/bash"),
        "the foreign hook's own shebang is restored as the first line"
    );
}

#[test]
fn broken_binary_foreign_hook_is_refused_not_corrupted() {
    let _l = lock();
    let r = setup("repo");
    let hook = r.root.join(".git/hooks/pre-commit");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    // A compiled (non-UTF-8) hook: chaining shell text into it would corrupt
    // it and change its semantics.
    let binary: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 0x00, 0xff, 0xfe, 0x01];
    std::fs::write(&hook, &binary).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    let result = hooks::install(&r.root, true);
    let after = std::fs::read(&hook).unwrap();
    assert!(
        result.is_err(),
        "a non-text hook must be refused as unsupported, not chained into"
    );
    assert_eq!(after, binary, "the existing hook must be left untouched");
}

#[test]
fn stale_default_install_reports_overridden_and_install_relocates() {
    let _l = lock();
    let r = setup("repo");

    // Install normally (default .git/hooks), THEN the user adopts a hook
    // manager that sets core.hooksPath — the old install becomes inert.
    hooks::install(&r.root, false).expect("initial install");
    git(&r.root, &["config", "core.hooksPath", ".custom-hooks"]);

    let status = hooks::status(&r.root).expect("status");
    assert_eq!(
        status.state,
        hooks::HookState::Overridden,
        "a shadowed install must be reported overridden, not installed"
    );
    assert!(!status.active, "an overridden hook is NOT active");
    assert!(
        status.detail.contains("hooksPath"),
        "the detail must explain the override: {}",
        status.detail
    );

    // A commit right now must NOT be scanned — and status said exactly that.
    let (_, scan_ran) = commit_with_stub(&r.root, &r.stub_dir, &r.marker, 0);
    assert!(
        !scan_ran,
        "git ignores the stale hook (that is the finding)"
    );

    // Re-install relocates the hook to where git looks and cleans the stale
    // copy.
    hooks::install(&r.root, false).expect("relocating install");
    let status = hooks::status(&r.root).expect("status");
    assert!(status.active, "after relocation protection is active");
    assert!(
        !r.root.join(".git/hooks/pre-commit").exists(),
        "the stale shadowed install is cleaned up"
    );
    let (committed, scan_ran) = commit_with_stub(&r.root, &r.stub_dir, &r.marker, 0);
    assert!(committed);
    assert!(scan_ran, "protection is genuinely active after relocation");
}

#[test]
fn status_reports_inactive_when_hook_lost_its_executable_bit() {
    let _l = lock();
    let r = setup("repo");
    hooks::install(&r.root, false).expect("install");
    let hook = r.root.join(".git/hooks/pre-commit");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();

    let status = hooks::status(&r.root).expect("status");
    assert!(
        !status.active,
        "a non-executable hook is ignored by git and must not be reported active"
    );
    assert!(
        status.detail.contains("not executable"),
        "detail must say why: {}",
        status.detail
    );
    // And the truth on the ground matches: the commit is not scanned.
    let (_, scan_ran) = commit_with_stub(&r.root, &r.stub_dir, &r.marker, 0);
    assert!(!scan_ran);
}

#[test]
fn hooks_path_with_spaces_is_safe() {
    let _l = lock();
    let r = setup("repo dir with spaces");
    git(&r.root, &["config", "core.hooksPath", "my hooks/dir"]);

    hooks::install(&r.root, false).expect("install into path with spaces");

    let (committed, scan_ran) = commit_with_stub(&r.root, &r.stub_dir, &r.marker, 0);
    assert!(committed);
    assert!(scan_ran, "scan must run from a hooksPath containing spaces");
    // The stub received the correct repo root even with spaces in the path.
    let recorded = std::fs::read_to_string(&r.marker).unwrap();
    let canon = r.root.canonicalize().unwrap();
    assert!(
        recorded.contains(canon.file_name().unwrap().to_str().unwrap()),
        "hook passed the repo root through correctly: {recorded}"
    );
}

#[test]
fn hook_falls_back_to_the_legacy_binary_name() {
    // A machine that only has the pre-rename `api-tracker` binary on PATH
    // (e.g. an old install) must still run the scan through the new hook.
    let _l = lock();
    let r = setup("repo");
    write_stub_named(&r.stub_dir, &["api-tracker"]);
    let _ = std::fs::remove_file(r.stub_dir.join("tethra"));
    hooks::install(&r.root, false).expect("install");
    // Hermetic PATH: stub dir + git's own dir + POSIX baseline. The real
    // PATH may carry an installed `tethra`, which the hook would prefer
    // over the legacy stub and the fallback would never be exercised.
    let git_dir = {
        let out = Command::new("sh")
            .args(["-c", "command -v git"])
            .output()
            .expect("locate git");
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        PathBuf::from(p).parent().map(|d| d.to_path_buf()).unwrap()
    };
    let path_env = format!(
        "{}:{}:/usr/bin:/bin",
        r.stub_dir.display(),
        git_dir.display()
    );
    let (ok, ran) = commit_with_stub_path(&r.root, &r.marker, 0, &path_env);
    assert!(ok, "clean scan lets the commit through");
    assert!(ran, "the legacy-named binary still runs the scan");
}

#[test]
fn legacy_installed_hook_is_recognized_and_upgraded() {
    // A hook installed by a pre-rename build (old body between the SAME
    // sentinels) must be reported as ours and replaced in place on
    // reinstall — never treated as a foreign hook.
    let _l = lock();
    let r = setup("repo");
    let hook = r.root.join(".git/hooks/pre-commit");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    let legacy_body = "#!/bin/sh\n# >>> api-tracker pre-commit hook >>>\n\
# Managed by API Tracker. Blocks commits containing high-confidence secrets.\n\
# Remove with: api-tracker hooks remove <path>\n\
if command -v api-tracker >/dev/null 2>&1; then\n\
  api-tracker scan --staged --hook \"$(git rev-parse --show-toplevel)\" || exit 1\n\
else\n\
  echo 'api-tracker not found on PATH; skipping secret pre-commit scan' >&2\n\
fi\n\
# <<< api-tracker pre-commit hook <<<\n";
    std::fs::write(&hook, legacy_body).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    let status = hooks::status(&r.root).expect("status");
    assert!(
        status.active,
        "legacy-format hook must be recognized as ours and active"
    );

    hooks::install(&r.root, false).expect("reinstall over legacy hook");
    let content = std::fs::read_to_string(&hook).unwrap();
    assert!(
        content.contains("tethra scan --staged --hook"),
        "upgraded hook prefers the tethra binary"
    );
    assert_eq!(
        content
            .matches(">>> api-tracker pre-commit hook >>>")
            .count(),
        1,
        "exactly one managed block after upgrade"
    );

    hooks::remove(&r.root).expect("remove upgraded hook");
    let content = std::fs::read_to_string(&hook).unwrap_or_default();
    assert!(
        !content.contains("pre-commit hook >>>"),
        "managed block removed"
    );
}
