//! RA-001 regression suite: repository configuration must never execute
//! code, on **any** path, including the automatic background one.
//!
//! # Why this file exists alongside `git_execution_canaries.rs`
//!
//! The older suite proved that the *automatic detection* path spawns
//! nothing, and that a list of enumerated configuration keys is
//! neutralized. It did not catch RA-001, for two reasons that this file
//! fixes:
//!
//! 1. **Its arming control was `armed.len() >= 2` of ten vectors.** Eight
//!    canaries could be permanently inert with the suite green, and several
//!    were inert by construction. Here, every vector declared *reachable*
//!    must fire under the mutation control — `>= 2` is replaced by "all of
//!    them", and a vector that cannot be armed is a test bug, not a pass.
//! 2. **Its control command set was not the product's.** It exercised
//!    `ls-files`, `check-ignore` and `status`, which Tethra never runs,
//!    while omitting `log -p`, which Tethra runs on a background timer and
//!    which is the command that verifies signatures. Here the control runs
//!    [`PRODUCT_COMMANDS`] — the exact argv the product builds.
//!
//! # The three-way check
//!
//! For every vector this suite asserts three things:
//!
//! * **armed** — plain `git` running the product's own argv against the
//!   hostile repository *does* execute the payload. Without this the other
//!   two assertions are vacuous.
//! * **sealed alone is enough** — the same argv, with `--git-dir` pointed
//!   at a [`gitseal`] directory and **no `-c` overrides at all**, does not.
//!   This is the load-bearing claim: the protection is structural, so it
//!   does not depend on having enumerated the right keys.
//! * **the product is clean** — the real public functions do not execute
//!   the payload, and still return correct results.
//!
//! The mutation check is therefore built in: "remove the isolation" is
//! precisely what the *armed* leg does, and it must fail closed.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use api_tracker_core::gitseal::{self, SealParts};

fn require_git() {
    let ok = Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(
        ok,
        "these canaries need a real `git` to build hostile fixtures; \
         without it this suite proves nothing"
    );
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

/// The exact argv Tethra builds, minus the leading hardening options.
///
/// Kept in one place so the control provably exercises the product's own
/// command set rather than a proxy for it. Sourced from
/// `crates/core/src/gitrepo.rs`: `head_commit`, `history_added_units`,
/// `range_added_units`, `envgov::history_probe`, `staged_files`,
/// `staged_blob`.
const PRODUCT_COMMANDS: &[&[&str]] = &[
    &["rev-parse", "HEAD"],
    &[
        "log",
        "-p",
        "--no-color",
        "-U0",
        "--no-merges",
        "--no-ext-diff",
        "--no-textconv",
        "--all",
    ],
    &[
        "log",
        "-p",
        "--no-color",
        "-U0",
        "--no-merges",
        "--no-ext-diff",
        "--no-textconv",
        "-n5",
    ],
    &["log", "--oneline", "-n", "1", "--all", "--", ".env"],
    &[
        "diff",
        "--cached",
        "--name-only",
        "--diff-filter=ACM",
        "--no-ext-diff",
        "--no-textconv",
        "-z",
    ],
    &["cat-file", "-s", ":.env"],
    &["show", ":.env"],
    &["config", "--get", "core.hooksPath"],
];

/// The same commands with the **flag-level** neutralizers removed.
///
/// `--no-ext-diff` and `--no-textconv` are a second, independent layer:
/// they make diff drivers and textconv filters inert regardless of where
/// the configuration came from. Keeping them in the probe would mask the
/// question this suite exists to answer — *does the sealing alone make
/// repository configuration inert?* — and masking it is precisely how the
/// previous suite's control came to over-approximate its own coverage.
///
/// So the arming control and the sealed-only check run these too. A vector
/// that fires here and not under the sealed directory is proof the
/// structural layer carries its own weight.
const ISOLATION_PROBE_COMMANDS: &[&[&str]] = &[
    &["log", "-p", "--no-color", "-U0", "--no-merges", "--all"],
    &["log", "-p", "--no-color", "-U0", "--no-merges", "-n5"],
    &["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
    &["show", ":.env"],
];

struct Fixture {
    _tmp: tempfile::TempDir,
    repo: PathBuf,
    canary: PathBuf,
    payload: PathBuf,
    /// The commit ids of the two ordinary commits, for range scanning.
    old: String,
    new: String,
}

impl Fixture {
    fn fired(&self) -> bool {
        self.canary.exists()
    }

    fn evidence(&self) -> String {
        std::fs::read_to_string(&self.canary).unwrap_or_default()
    }

    fn reset(&self) {
        let _ = std::fs::remove_file(&self.canary);
    }

    fn git_config_append(&self, text: &str) {
        let path = self.repo.join(".git/config");
        let mut cfg = std::fs::read_to_string(&path).unwrap_or_default();
        cfg.push_str(text);
        std::fs::write(&path, cfg).unwrap();
    }

    /// The payload, spelled the way a hostile configuration value would.
    fn payload_str(&self) -> String {
        self.payload.display().to_string()
    }
}

/// A repository with real content, an executable payload, and a HEAD commit
/// carrying a fabricated `gpgsig` header.
///
/// The signature does not have to be valid: Git pattern-matches the header
/// and then hands the blob to whatever program the configuration names.
/// Building this shape is what makes the signature-verifier vectors
/// reachable at all.
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("hostile");
    std::fs::create_dir_all(&repo).unwrap();
    let canary = tmp.path().join("CANARY_FIRED.txt");
    let payload = repo.join("payload.sh");
    std::fs::write(
        &payload,
        format!(
            "#!/bin/sh\nprintf 'PAYLOAD EXECUTED argv=%s\\n' \"$*\" >> {}\nexit 0\n",
            canary.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(git(&repo, &["init", "-q", "."]).status.success());
    assert!(git(&repo, &["config", "user.name", "t"]).status.success());
    assert!(git(&repo, &["config", "user.email", "t@example.invalid"])
        .status
        .success());

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
    // Commit before anything hostile is armed: `core.fsmonitor` is only
    // consulted when Git refreshes an index against a working tree, so an
    // empty index would leave that vector unreachable and the suite vacuous.
    assert!(git(&repo, &["add", ".env", "package.json"])
        .status
        .success());
    assert!(git(&repo, &["commit", "-q", "-m", "init"]).status.success());
    let old = rev(&repo, "HEAD");

    std::fs::write(
        repo.join(".env"),
        "OPENAI_API_KEY=sk-proj-FAKECANARY111111111111111111111111\n",
    )
    .unwrap();
    assert!(git(&repo, &["add", ".env"]).status.success());
    assert!(git(&repo, &["commit", "-q", "-m", "second"])
        .status
        .success());

    // Something staged but not committed, so `diff --cached` and
    // `show :path` have real work to do.
    std::fs::write(repo.join("staged.env"), "STRIPE_SECRET_KEY=sk_live_FAKE\n").unwrap();
    assert!(git(&repo, &["add", "staged.env"]).status.success());

    let new = sign_head(&repo);
    Fixture {
        _tmp: tmp,
        repo,
        canary,
        payload,
        old,
        new,
    }
}

fn rev(repo: &Path, what: &str) -> String {
    String::from_utf8(git(repo, &["rev-parse", what]).stdout)
        .unwrap()
        .trim()
        .to_string()
}

/// Move HEAD onto a commit carrying an OpenPGP-shaped `gpgsig` header.
fn sign_head(repo: &Path) -> String {
    sign_head_as(repo, SignatureShape::OpenPgp)
}

/// Which signature format the fabricated header advertises.
///
/// Git chooses the verifier program from the **payload's own header**, not
/// from `gpg.format`, so each verifier vector has to ship the matching
/// shape. Getting this wrong is how three of these canaries were silently
/// inert on the first run of this suite — the arming control caught it.
#[derive(Clone, Copy)]
enum SignatureShape {
    OpenPgp,
    Ssh,
    X509,
}

impl SignatureShape {
    fn header(self) -> (&'static str, &'static str) {
        match self {
            SignatureShape::OpenPgp => (
                "-----BEGIN PGP SIGNATURE-----",
                "-----END PGP SIGNATURE-----",
            ),
            SignatureShape::Ssh => (
                "-----BEGIN SSH SIGNATURE-----",
                "-----END SSH SIGNATURE-----",
            ),
            SignatureShape::X509 => (
                "-----BEGIN SIGNED MESSAGE-----",
                "-----END SIGNED MESSAGE-----",
            ),
        }
    }
}

fn sign_head_as(repo: &Path, shape: SignatureShape) -> String {
    let tree = rev(repo, "HEAD^{tree}");
    let parent = rev(repo, "HEAD");
    let (begin, end) = shape.header();
    let commit = format!(
        "tree {tree}\nparent {parent}\n\
         author t <t@example.invalid> 1700000000 +0000\n\
         committer t <t@example.invalid> 1700000000 +0000\n\
         gpgsig {begin}\n \n U1NIU0lHAAAAAQ\n {end}\n\nsigned commit\n"
    );
    let mut child = Command::new("git")
        .args(["hash-object", "-t", "commit", "-w", "--stdin"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(commit.as_bytes())
            .unwrap();
    }
    let oid = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    let oid = oid.trim().to_string();
    assert!(git(repo, &["update-ref", "HEAD", &oid]).status.success());
    oid
}

// ---------------------------------------------------------------------------
// The vectors
// ---------------------------------------------------------------------------

/// `reachable` records whether this vector can fire against the *product's
/// own command set* when isolation is removed.
///
/// Only reachable vectors carry a meaningful mutation control, and every
/// one of them must fire — see [`every_reachable_vector_is_armed`]. The
/// unreachable ones are still asserted clean (cheap, and they guard against
/// a future command being added that would reach them), but they are
/// labelled honestly rather than padding an "N of M" threshold.
struct Vector {
    name: &'static str,
    arm: fn(&Fixture),
    reachable: bool,
    /// Why an unreachable vector cannot fire. Empty for reachable ones.
    why_unreachable: &'static str,
}

fn arm_log_show_signature(fx: &Fixture) {
    fx.git_config_append(&format!(
        "[log]\n\tshowSignature = true\n[gpg]\n\tprogram = {}\n",
        fx.payload_str()
    ));
}

fn arm_gpg_openpgp_program(fx: &Fixture) {
    sign_head_as(&fx.repo, SignatureShape::OpenPgp);
    fx.git_config_append(&format!(
        "[log]\n\tshowSignature = true\n[gpg]\n\tformat = openpgp\n\
         [gpg \"openpgp\"]\n\tprogram = {}\n",
        fx.payload_str()
    ));
}

fn arm_gpg_ssh_program(fx: &Fixture) {
    sign_head_as(&fx.repo, SignatureShape::Ssh);
    // Git refuses SSH verification outright unless an allowed-signers file
    // is configured AND exists, so the vector is unreachable — and the
    // canary silently inert — without one.
    let signers = fx.repo.join("allowed_signers");
    std::fs::write(
        &signers,
        "signer@example.invalid ssh-ed25519 \
         AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleEx\n",
    )
    .unwrap();
    fx.git_config_append(&format!(
        "[log]\n\tshowSignature = true\n[gpg]\n\tformat = ssh\n\
         [gpg \"ssh\"]\n\tprogram = {}\n\tallowedSignersFile = {}\n",
        fx.payload_str(),
        signers.display()
    ));
}

fn arm_gpg_x509_program(fx: &Fixture) {
    sign_head_as(&fx.repo, SignatureShape::X509);
    fx.git_config_append(&format!(
        "[log]\n\tshowSignature = true\n[gpg]\n\tformat = x509\n\
         [gpg \"x509\"]\n\tprogram = {}\n",
        fx.payload_str()
    ));
}

/// The repository's own `.git/config` — the file a hostile repository
/// actually ships, and the one no `GIT_CONFIG_*` variable can switch off.
fn arm_repo_local_config(fx: &Fixture) {
    fx.git_config_append(&format!(
        "[core]\n\tfsmonitor = {p}\n[log]\n\tshowSignature = true\n[gpg]\n\tprogram = {p}\n",
        p = fx.payload_str()
    ));
}

/// Configuration reached through `include.path` from the repository's own
/// config: an indirection the key-by-key overrides never see.
fn arm_included_config(fx: &Fixture) {
    let included = fx.repo.join(".git/included-config");
    std::fs::write(
        &included,
        format!(
            "[log]\n\tshowSignature = true\n[gpg]\n\tprogram = {}\n[core]\n\tfsmonitor = {}\n",
            fx.payload_str(),
            fx.payload_str()
        ),
    )
    .unwrap();
    fx.git_config_append("[include]\n\tpath = included-config\n");
}

/// `$GIT_DIR/config.worktree`, enabled by `extensions.worktreeConfig`.
fn arm_worktree_config(fx: &Fixture) {
    fx.git_config_append("[extensions]\n\tworktreeConfig = true\n");
    std::fs::write(
        fx.repo.join(".git/config.worktree"),
        format!(
            "[log]\n\tshowSignature = true\n[gpg]\n\tprogram = {}\n",
            fx.payload_str()
        ),
    )
    .unwrap();
}

fn arm_fsmonitor(fx: &Fixture) {
    fx.git_config_append(&format!("[core]\n\tfsmonitor = {}\n", fx.payload_str()));
}

fn arm_hooks(fx: &Fixture) {
    let hooks = fx.repo.join("evil-hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for name in [
        "pre-commit",
        "post-checkout",
        "post-index-change",
        "reference-transaction",
        "post-applypatch",
    ] {
        let hook = hooks.join(name);
        std::fs::write(
            &hook,
            format!("#!/bin/sh\nexec {} hook\n", fx.payload_str()),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    fx.git_config_append(&format!("[core]\n\thooksPath = {}\n", hooks.display()));
}

fn arm_filters(fx: &Fixture) {
    std::fs::write(fx.repo.join(".gitattributes"), "* filter=evil\n").unwrap();
    fx.git_config_append(&format!(
        "[filter \"evil\"]\n\tclean = {p} clean\n\tsmudge = {p} smudge\n\tprocess = {p} process\n",
        p = fx.payload_str()
    ));
}

fn arm_diff_driver(fx: &Fixture) {
    std::fs::write(fx.repo.join(".gitattributes"), "* diff=evil\n").unwrap();
    fx.git_config_append(&format!(
        "[diff \"evil\"]\n\tcommand = {p} driver\n",
        p = fx.payload_str()
    ));
}

fn arm_textconv(fx: &Fixture) {
    std::fs::write(fx.repo.join(".gitattributes"), "* diff=evil\n").unwrap();
    fx.git_config_append(&format!(
        "[diff \"evil\"]\n\ttextconv = {p} textconv\n",
        p = fx.payload_str()
    ));
}

fn arm_external_diff(fx: &Fixture) {
    fx.git_config_append(&format!(
        "[diff]\n\texternal = {p} external\n",
        p = fx.payload_str()
    ));
}

fn arm_pager(fx: &Fixture) {
    fx.git_config_append(&format!(
        "[core]\n\tpager = {p} pager\n[pager]\n\tlog = {p} pagerlog\n\tdiff = {p} pagerdiff\n",
        p = fx.payload_str()
    ));
}

fn arm_editor(fx: &Fixture) {
    fx.git_config_append(&format!(
        "[core]\n\teditor = {p} editor\n[sequence]\n\teditor = {p} seq\n",
        p = fx.payload_str()
    ));
}

fn arm_credential_helper(fx: &Fixture) {
    fx.git_config_append(&format!(
        "[credential]\n\thelper = {p} cred\n[core]\n\taskPass = {p} askpass\n",
        p = fx.payload_str()
    ));
}

const VECTORS: &[Vector] = &[
    Vector {
        name: "log.showSignature + gpg.program (RA-001)",
        arm: arm_log_show_signature,
        reachable: true,
        why_unreachable: "",
    },
    Vector {
        name: "OpenPGP verifier program",
        arm: arm_gpg_openpgp_program,
        reachable: true,
        why_unreachable: "",
    },
    Vector {
        name: "SSH signature verifier program",
        arm: arm_gpg_ssh_program,
        reachable: true,
        why_unreachable: "",
    },
    Vector {
        name: "X.509 signature verifier program",
        arm: arm_gpg_x509_program,
        reachable: true,
        why_unreachable: "",
    },
    Vector {
        name: "repository-local .git/config",
        arm: arm_repo_local_config,
        reachable: true,
        why_unreachable: "",
    },
    Vector {
        name: "included config (include.path)",
        arm: arm_included_config,
        reachable: true,
        why_unreachable: "",
    },
    Vector {
        name: "worktree config (extensions.worktreeConfig)",
        arm: arm_worktree_config,
        reachable: true,
        why_unreachable: "",
    },
    Vector {
        name: "core.fsmonitor",
        arm: arm_fsmonitor,
        reachable: true,
        why_unreachable: "",
    },
    Vector {
        name: "textconv",
        arm: arm_textconv,
        reachable: true,
        why_unreachable: "",
    },
    Vector {
        name: "external diff driver (diff.external)",
        arm: arm_external_diff,
        reachable: false,
        why_unreachable: "git 2.50.1 invokes diff.external only for a bare working-tree \
                          `git diff`; it does not for `diff --cached`, `diff <rev>`, `show` \
                          or `log -p`, and a bare `git diff` is not in the product's command \
                          set. Measured, not assumed.",
    },
    Vector {
        name: "named diff driver command (diff.<d>.command)",
        arm: arm_diff_driver,
        reachable: false,
        why_unreachable: "same measurement as diff.external: the named driver's `command` is \
                          reached through the same external-diff path, which none of the \
                          product's commands take. Its sibling `textconv` IS reachable and \
                          is armed separately.",
    },
    Vector {
        name: "hooks (core.hooksPath)",
        arm: arm_hooks,
        reachable: false,
        why_unreachable: "no command Tethra runs writes a ref, commits, checks out, or \
                          refreshes the index in a way that fires a hook",
    },
    Vector {
        name: "clean/smudge filters",
        arm: arm_filters,
        reachable: false,
        why_unreachable: "clean runs on check-in and smudge on checkout; Tethra only \
                          compares blob sets and emits blobs raw",
    },
    Vector {
        name: "pager",
        arm: arm_pager,
        reachable: false,
        why_unreachable: "stdout is always a pipe and --no-pager is always passed, so Git \
                          launches no pager",
    },
    Vector {
        name: "editor",
        arm: arm_editor,
        reachable: false,
        why_unreachable: "core.editor and sequence.editor are launched only by commands that \
                          ask the user to compose a message or edit a todo list (commit, tag, \
                          rebase -i, am). Every command in PRODUCT_COMMANDS is read-only and \
                          runs with stdin closed.",
    },
    Vector {
        name: "credential helper / askPass",
        arm: arm_credential_helper,
        reachable: false,
        why_unreachable: "no command Tethra runs contacts a remote, so Git never decides it \
                          needs authentication",
    },
];

// ---------------------------------------------------------------------------
// Runners
// ---------------------------------------------------------------------------

/// Baseline environment shared by every runner below, so the three legs
/// differ ONLY in whether the repository's configuration participates.
fn base_env(cmd: &mut Command) {
    cmd.current_dir(std::env::temp_dir());
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("LC_ALL", "C");
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
}

/// **The mutation control.** Plain `git -C <repo>` running the product's own
/// argv: isolation removed, nothing else changed.
fn run_unisolated(fx: &Fixture, args: &[&str]) {
    let mut cmd = Command::new("git");
    base_env(&mut cmd);
    cmd.arg("--no-pager").arg("-C").arg(&fx.repo).args(args);
    let _ = cmd.output();
}

/// The structural protection ALONE: a sealed directory, and deliberately
/// **no `-c` overrides**, so a pass cannot be credited to the enumeration.
fn run_sealed_only(fx: &Fixture, args: &[&str]) -> bool {
    let parts = if args.iter().any(|a| a.starts_with(':') || *a == "--cached") {
        SealParts::with_index()
    } else {
        SealParts::refs_only()
    };
    let Ok(sealed) = gitseal::seal(&fx.repo, parts) else {
        return false;
    };
    let mut cmd = Command::new("git");
    base_env(&mut cmd);
    cmd.arg("--no-pager")
        .arg("--git-dir")
        .arg(sealed.git_dir())
        .args(args);
    let _ = cmd.output();
    true
}

/// Every public entry point that reaches Git, plus the automatic paths that
/// must reach nothing.
fn run_product_paths(fx: &Fixture) {
    use api_tracker_core::{envgov, gitrepo, gitsafe};
    // Automatic detection / folder selection: spawns nothing at all.
    let _ = envgov::discover(&fx.repo);
    let _ = envgov::discover_bounded(
        &fx.repo,
        envgov::DiscoveryLimits::default(),
        envgov::HistoryProbe::Skip,
    );
    let _ = envgov::gitignore_protects(&fx.repo, ".env");
    if let Ok(canonical) = fx.repo.canonicalize() {
        if let Some(view) = gitsafe::RepoView::open(&canonical) {
            let _ = view.status_of(&canonical.join(".env"));
        }
    }
    // Deliberate, user-invoked Git paths.
    let _ = gitrepo::repo_root(&fx.repo);
    let _ = gitrepo::head_commit(&fx.repo);
    let _ = gitrepo::staged_files(&fx.repo);
    let _ = gitrepo::staged_units(&fx.repo);
    let _ = gitrepo::staged_blob(&fx.repo, ".env");
    let _ = gitrepo::history_added_units(&fx.repo, Some(5));
    let _ = gitrepo::history_added_units(&fx.repo, None);
    let _ = gitrepo::collect_full_repo_scan(&fx.repo);
    let _ = gitrepo::config_get(&fx.repo, "core.hooksPath");
    let _ = envgov::discover_bounded(
        &fx.repo,
        envgov::DiscoveryLimits::default(),
        envgov::HistoryProbe::HardenedGit,
    );
    // The background-monitor path: HEAD has advanced onto the hostile
    // signed commit, so this is the incremental range scan that RA-001
    // reproduced through.
    let _ = gitrepo::range_added_units(&fx.repo, &fx.old, &fx.new);
    let _ = gitrepo::git_available();
}

// ---------------------------------------------------------------------------
// The properties
// ---------------------------------------------------------------------------

/// Without this, every other assertion in the file is vacuous.
///
/// Replaces the old suite's `armed.len() >= 2` of ten: **every** vector
/// declared reachable must fire against the product's own command set when
/// the isolation is removed.
#[test]
fn every_reachable_vector_is_armed() {
    require_git();
    let mut not_armed = Vec::new();
    for vector in VECTORS {
        if !vector.reachable {
            continue;
        }
        let fx = fixture();
        (vector.arm)(&fx);
        fx.reset();
        for args in PRODUCT_COMMANDS.iter().chain(ISOLATION_PROBE_COMMANDS) {
            run_unisolated(&fx, args);
        }
        if !fx.fired() {
            not_armed.push(vector.name);
        }
    }
    assert!(
        not_armed.is_empty(),
        "these vectors are declared reachable but did NOT fire against the product's own \
         command set with isolation removed, so the corresponding protection assertions \
         prove nothing: {not_armed:?}"
    );
}

/// A vector excused from the arming control must say, specifically, why it
/// cannot fire — otherwise "unreachable" becomes a place to hide a canary
/// that simply stopped working, which is the failure mode that let RA-001
/// through the previous suite.
#[test]
fn every_unreachable_vector_states_a_specific_reason() {
    let mut reachable = 0usize;
    for vector in VECTORS {
        if vector.reachable {
            reachable += 1;
            assert!(
                vector.why_unreachable.is_empty(),
                "{} is reachable, so it must not carry an excuse",
                vector.name
            );
        } else {
            assert!(
                vector.why_unreachable.len() > 60,
                "{} is excused from the arming control with no specific, measured reason: {:?}",
                vector.name,
                vector.why_unreachable
            );
        }
    }
    // The signature-verifier class that RA-001 exploited must never quietly
    // become "unreachable".
    for required in [
        "log.showSignature + gpg.program (RA-001)",
        "OpenPGP verifier program",
        "SSH signature verifier program",
        "X.509 signature verifier program",
        "repository-local .git/config",
        "included config (include.path)",
        "worktree config (extensions.worktreeConfig)",
        "core.fsmonitor",
    ] {
        let vector = VECTORS
            .iter()
            .find(|v| v.name == required)
            .unwrap_or_else(|| panic!("{required} must remain covered"));
        assert!(
            vector.reachable,
            "{required} must stay in the armed set - it is the RA-001 class"
        );
    }
    assert!(
        reachable >= 9,
        "only {reachable} vectors are armed; the suite has lost coverage"
    );
}

/// The load-bearing claim: the sealed directory alone closes every vector,
/// with no `-c` override in play.
#[test]
fn sealing_alone_closes_every_vector() {
    require_git();
    for vector in VECTORS {
        let fx = fixture();
        (vector.arm)(&fx);
        fx.reset();
        let mut sealed_ok = false;
        for args in PRODUCT_COMMANDS.iter().chain(ISOLATION_PROBE_COMMANDS) {
            // `config --get` is the documented read-through exception and
            // has no sealed form; it is covered by the product test below.
            if args.first() == Some(&"config") {
                continue;
            }
            sealed_ok |= run_sealed_only(&fx, args);
        }
        assert!(
            sealed_ok,
            "sealing failed outright for {} - a refusal is safe, but this test then \
             proves nothing about isolation",
            vector.name
        );
        assert!(
            !fx.fired(),
            "STRUCTURAL ISOLATION FAILED for {}: the sealed directory alone must make this \
             vector inert. Evidence: {}",
            vector.name,
            fx.evidence()
        );
    }
}

/// The product's real entry points, including the automatic background one.
#[test]
fn no_product_path_executes_repository_controlled_code() {
    require_git();
    for vector in VECTORS {
        let fx = fixture();
        (vector.arm)(&fx);
        fx.reset();
        run_product_paths(&fx);
        assert!(
            !fx.fired(),
            "A PRODUCT PATH EXECUTED REPOSITORY-CONTROLLED CODE via {}: {}",
            vector.name,
            fx.evidence()
        );
    }
}

/// The exact RA-001 chain: a folder registered by the Track flow, scanned
/// by the desktop's background monitor after HEAD advances onto a commit
/// the attacker pushed.
#[test]
fn the_background_monitor_path_is_clean_after_head_advances() {
    require_git();
    let fx = fixture();
    arm_log_show_signature(&fx);

    // First tick: baseline only, nothing executed and nothing scanned.
    fx.reset();
    let baseline = api_tracker_core::gitrepo::head_commit(&fx.repo);
    assert!(
        !fx.fired(),
        "baseline head_commit executed code: {}",
        fx.evidence()
    );
    let baseline = baseline.expect("head_commit must still work on a hostile repo");

    // The attacker pushes another signature-shaped commit; the victim pulls.
    let advanced = sign_head(&fx.repo);
    assert_ne!(baseline, advanced, "HEAD must actually advance");

    // The next monitor tick scans the new range.
    fx.reset();
    let scan = api_tracker_core::gitrepo::range_added_units(&fx.repo, &baseline, &advanced)
        .expect("the incremental range scan must still succeed");
    assert!(
        !fx.fired(),
        "SECURITY: the background monitor executed repository-controlled code after HEAD \
         advanced. Evidence: {}",
        fx.evidence()
    );
    // Coverage must be honest, not merely silent.
    assert!(
        scan.complete,
        "the sealed range scan reported incomplete coverage: {:?}",
        scan.warnings
    );
}

/// Isolation must not cost correctness: the sealed view has to return the
/// same content an unsealed read would.
#[test]
fn the_sealed_view_still_sees_the_repositorys_real_content() {
    require_git();
    let fx = fixture();
    arm_repo_local_config(&fx);
    fx.reset();

    let root = api_tracker_core::gitrepo::repo_root(&fx.repo).expect("repo_root");
    assert_eq!(
        root.canonicalize().unwrap(),
        fx.repo.canonicalize().unwrap(),
        "repo_root must resolve the work tree without running git"
    );

    let head = api_tracker_core::gitrepo::head_commit(&fx.repo).expect("head_commit");
    assert_eq!(head, fx.new, "head_commit must agree with the real HEAD");

    let staged = api_tracker_core::gitrepo::staged_files(&fx.repo).expect("staged_files");
    assert!(
        staged.iter().any(|p| p == "staged.env"),
        "the sealed index view must list staged files: {staged:?}"
    );

    let blob = api_tracker_core::gitrepo::staged_blob(&fx.repo, "staged.env")
        .expect("staged_blob")
        .expect("staged.env is staged");
    assert!(
        String::from_utf8_lossy(&blob).contains("sk_live_FAKE"),
        "the sealed index view must return staged content"
    );

    let history = api_tracker_core::gitrepo::history_added_units(&fx.repo, None).expect("history");
    assert!(
        history.units.iter().any(|u| u
            .content
            .contains("sk-proj-FAKECANARY111111111111111111111111")),
        "the sealed history view must find committed content: {:?}",
        history.units.iter().map(|u| &u.label).collect::<Vec<_>>()
    );
    assert!(
        !fx.fired(),
        "content checks executed code: {}",
        fx.evidence()
    );
}

/// A repository whose format the seal cannot reproduce must be refused,
/// not silently retried against its own configuration.
#[test]
fn an_unreproducible_repository_is_refused_rather_than_trusted() {
    require_git();
    let fx = fixture();
    arm_log_show_signature(&fx);
    // An extension outside the validated allowlist.
    fx.git_config_append("[extensions]\n\tpartialClone = origin\n");
    let path = fx.repo.join(".git/config");
    let cfg = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        cfg.replace("repositoryformatversion = 0", "repositoryformatversion = 1"),
    )
    .unwrap();

    fx.reset();
    let err = api_tracker_core::gitrepo::head_commit(&fx.repo)
        .expect_err("an unreproducible repository must be refused");
    let text = err.to_string();
    assert!(
        text.contains("partialclone"),
        "the refusal must name the extension it could not reproduce: {text}"
    );
    assert!(
        text.contains("will not fall back"),
        "the refusal must state that it does not degrade to the repository's own \
         configuration: {text}"
    );
    assert!(
        !fx.fired(),
        "the refusal path itself executed code: {}",
        fx.evidence()
    );
}

/// Git is never invoked through a shell, and the sealed configuration never
/// names a program.
#[test]
fn the_sealed_configuration_names_no_program() {
    require_git();
    let fx = fixture();
    arm_repo_local_config(&fx);
    let sealed = gitseal::seal(&fx.repo, SealParts::with_index()).expect("seal");
    let config = std::fs::read_to_string(sealed.git_dir().join("config")).expect("sealed config");
    for forbidden in [
        "payload",
        "fsmonitor",
        "gpg",
        "showSignature",
        "hooksPath",
        "include",
        "filter",
        "textconv",
        "external",
        "helper",
        "askPass",
        "editor",
        "pager",
    ] {
        assert!(
            !config.contains(forbidden),
            "the sealed config must not mention {forbidden}:\n{config}"
        );
    }
    // And the repository's own config must not have been copied in.
    assert!(
        !sealed.git_dir().join("config.worktree").exists(),
        "the seal must not carry a worktree config"
    );
}

/// The seal is a throwaway: it must never write into the user's repository.
#[test]
fn sealed_reads_never_modify_the_repository() {
    require_git();
    let fx = fixture();
    arm_repo_local_config(&fx);

    let digest = |root: &Path| -> Vec<(String, u64, std::time::SystemTime)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(meta) = entry.metadata() else { continue };
                if meta.is_dir() {
                    stack.push(entry.path());
                } else {
                    out.push((
                        entry.path().display().to_string(),
                        meta.len(),
                        meta.modified().unwrap_or(std::time::UNIX_EPOCH),
                    ));
                }
            }
        }
        out.sort();
        out
    };

    let git_dir = fx.repo.join(".git");
    let before = digest(&git_dir);
    for _ in 0..3 {
        run_product_paths(&fx);
    }
    let after = digest(&git_dir);
    assert_eq!(
        before, after,
        "sealed reads must leave the repository's .git byte-identical"
    );
}
