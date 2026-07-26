//! `tethra run` — secure process injection, optionally with runtime
//! observation.
//!
//! Decrypts only the selected credentials of one project and injects them
//! into the child process's environment. Values are never written to disk,
//! never printed, and unrelated project credentials are never injected. The
//! child inherits the parent environment plus the injected variables; when it
//! exits the values are gone (the child's environment dies with it and the
//! in-process `SecretString` buffers are zeroized on drop).
//!
//! With `--observe`, the run is additionally monitored: a loopback proxy
//! observes the child's API traffic and records sanitized, metadata-only
//! records. Existing non-observed runs behave exactly as before.

use crate::ctx::Ctx;
use anyhow::{anyhow, bail, Result};
use api_tracker_core::runtime::model::ObservationMode;
use clap::Args;

#[derive(Args)]
pub struct RunArgs {
    /// Project whose credentials may be injected.
    #[arg(long, required_unless_present = "grant", conflicts_with = "grant")]
    pub project: Option<String>,
    /// Run under a temporary access grant (see `access grant`).
    #[arg(long)]
    pub grant: Option<String>,
    /// Credential selector(s) to inject. Pair each with a matching --env.
    #[arg(long = "credential", value_name = "CREDENTIAL")]
    pub credentials: Vec<String>,
    /// Environment-variable name(s), paired positionally with --credential.
    #[arg(long = "env", value_name = "VAR")]
    pub envs: Vec<String>,
    /// Observe the run's API traffic (metadata only). `--observe` alone means
    /// metadata mode; `--observe=connection` records connections without
    /// decrypting HTTPS; `--observe=off` (the default) does not observe.
    #[arg(long, num_args = 0..=1, default_missing_value = "metadata", value_name = "MODE")]
    pub observe: Option<String>,
    /// The command to run, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

fn parse_observe_mode(observe: &Option<String>) -> Result<Option<ObservationMode>> {
    match observe {
        None => Ok(None),
        Some(s) => match ObservationMode::parse(s) {
            Some(ObservationMode::Off) => Ok(None),
            Some(m) => Ok(Some(m)),
            None => bail!("invalid --observe mode '{s}' (use off|connection|metadata)"),
        },
    }
}

pub fn run(ctx: &Ctx, args: RunArgs) -> Result<()> {
    if args.credentials.len() != args.envs.len() {
        bail!(
            "each --credential must be paired with an --env (got {} credentials, {} env names)",
            args.credentials.len(),
            args.envs.len()
        );
    }
    let explicit: Vec<(String, String)> = args
        .credentials
        .iter()
        .cloned()
        .zip(args.envs.iter().cloned())
        .collect();

    if let Some(mode) = parse_observe_mode(&args.observe)? {
        return run_observed(ctx, &args, explicit, mode);
    }

    let (vault, _token) = ctx.unlocked()?;
    let command_label = api_tracker_core::runtime::sanitize::redact_command(&args.command);
    let (env, session, grant_limits) = match &args.grant {
        Some(grant_id) => {
            if !args.credentials.is_empty() {
                bail!("--credential cannot be combined with --grant (the grant decides)");
            }
            let injection = vault.build_injection_with_grant(grant_id, &command_label)?;
            for warning in &injection.warnings {
                eprintln!("{warning}");
            }
            (
                injection.env,
                injection.session_id,
                Some((grant_id.clone(), injection.max_duration_secs)),
            )
        }
        None => {
            let project = args
                .project
                .as_deref()
                .expect("clap enforces project|grant");
            let (env, session) = vault.build_injection(project, &explicit, &command_label)?;
            (env, session, None)
        }
    };

    let injected_names: Vec<&str> = env.iter().map(|(v, _)| v.as_str()).collect();
    eprintln!(
        "Injecting {} credential(s) into the environment: {}",
        env.len(),
        injected_names.join(", ")
    );

    let program = &args.command[0];
    let mut cmd = std::process::Command::new(program);
    cmd.args(&args.command[1..]);
    // Do NOT leak Tethra's own secret environment (passwords, the
    // session token, admin keys) into the child. Deny-by-default over the
    // whole TETHRA_/API_TRACKER_ prefix pair — an enumerated list here once missed
    // API_TRACKER_NEW_PASSWORD (PI-01). The child inherits the rest of the
    // parent environment plus only the credentials we inject.
    api_tracker_core::inject::scrub_own_env(&mut cmd);
    for (name, value) in &env {
        // The secret is set on the child's environment only.
        cmd.env(name, value.expose());
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            let _ = vault.end_process_session(&session, None);
            bail!("failed to run '{program}': {e}");
        }
    };
    // env (with its SecretStrings) drops here, zeroizing the values.
    drop(env);
    let (grant_id, max_duration) = match &grant_limits {
        Some((id, secs)) => (Some(id.as_str()), *secs),
        None => (None, None),
    };
    let _ = vault.record_session_pid(&session, child.id(), grant_id);

    // Wait, enforcing the grant's per-process time bound where set.
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {
                if let Some(secs) = max_duration {
                    if started.elapsed().as_secs() >= secs.max(0) as u64 {
                        eprintln!(
                            "Grant time limit ({secs}s) reached — terminating the child.                              (This is a LOCAL bound; the credential itself remains valid.)"
                        );
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = vault.end_process_session(&session, Some(124));
                        std::process::exit(124);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => break Err(e),
        }
    };

    let (code, summary): (Option<i32>, String) = match status {
        Ok(s) => (s.code(), describe_status(&s)),
        Err(e) => {
            let _ = vault.end_process_session(&session, None);
            bail!("failed to wait for '{program}': {e}");
        }
    };
    // Best-effort session bookkeeping — never lose the child's exit code if
    // the DB write fails.
    if let Err(e) = vault.end_process_session(&session, code) {
        eprintln!("warning: could not record process session end: {e}");
    }
    eprintln!("Child process {summary}.");
    std::process::exit(code.unwrap_or(1));
}

/// The monitored-run path. Existing non-observed behavior is untouched; this is
/// a separate branch.
fn run_observed(
    ctx: &Ctx,
    args: &RunArgs,
    explicit: Vec<(String, String)>,
    mode: ObservationMode,
) -> Result<()> {
    if args.grant.is_some() {
        bail!("--observe is not yet supported with --grant; use --project");
    }
    let project = args
        .project
        .as_deref()
        .expect("clap enforces project|grant, and grant is barred above");

    let (vault, token) = ctx.unlocked()?;
    let command_label = api_tracker_core::runtime::sanitize::redact_command(&args.command);

    // Build the credential injection through the vetted path (this decrypts
    // only the mapped/explicit credentials and creates a process-session row,
    // which we close immediately since the observation session is the record).
    let (env, proc_session) = vault.build_injection(project, &explicit, &command_label)?;
    let injected_names: Vec<String> = env.iter().map(|(v, _)| v.clone()).collect();

    // Resolve the injected credential ids + their versions for attribution.
    let cred_ids = resolve_credential_ids(&vault, project, &explicit)?;
    let injected = vault.observe_injected(&cred_ids)?;
    let allowlist: Vec<(String, u16)> = vault
        .observe_allowlist(project)?
        .into_iter()
        .map(|(h, p, _)| (h, p))
        .collect();
    let project_id = vault.get_project(project)?.id;

    let program = args.command[0].clone();
    let mut cmd = std::process::Command::new(&program);
    cmd.args(&args.command[1..]);
    api_tracker_core::inject::scrub_own_env(&mut cmd);
    for (name, value) in &env {
        cmd.env(name, value.expose());
    }
    drop(env); // zeroizes the injected values; the child already has copies
    let _ = vault.end_process_session(&proc_session, None);

    eprintln!(
        "Observing this run in {mode} mode. Metadata only — request/response bodies, header \
         values, cookies, query strings, and secrets are never stored."
    );
    if !injected_names.is_empty() {
        eprintln!(
            "Injecting {} credential(s): {}",
            injected_names.len(),
            injected_names.join(", ")
        );
    }
    if !allowlist.is_empty() {
        eprintln!(
            "WARNING: {} internal destination(s) are allowlisted for this project; \
             traffic to them bypasses the private-address block.",
            allowlist.len()
        );
    }

    // Lock policy: a long-running observed run must stop if the vault locks.
    // Under a session token, watch that session file (manual `lock` deletes it;
    // auto-lock is its recorded expiry) — the run inherits exactly the lock
    // behavior it was started under. With an inline password there is no shared
    // session file, so bound the run by the vault's auto-lock TTL from start.
    let lock = if token.is_some() {
        api_tracker_observe::session::LockPolicy {
            session_file: Some(vault.paths().session_path()),
            max_run: None,
        }
    } else {
        let mins = vault.settings().auto_lock_minutes;
        api_tracker_observe::session::LockPolicy {
            session_file: None,
            max_run: (mins > 0).then(|| std::time::Duration::from_secs(u64::from(mins) * 60)),
        }
    };

    let params = api_tracker_observe::session::RunParams {
        project_id,
        mode,
        source: "cli_run".to_string(),
        command_label,
        credential_names: injected_names,
        injected,
        allowlist,
        lock,
    };
    let outcome = api_tracker_observe::session::run_monitored(&vault, params, cmd, &program)
        .map_err(|e| anyhow!("{e}"))?;

    let session = vault.observe_session(&outcome.session_id)?;
    let short = &outcome.session_id[..8.min(outcome.session_id.len())];
    if let Some(reason) = &outcome.interrupt_reason {
        let cause = match reason.as_str() {
            "vault_locked" => "the vault was locked",
            "auto_lock" => "the vault auto-locked",
            other => other,
        };
        eprintln!(
            "Monitored session {short} INTERRUPTED — {cause}: the observation proxy was shut \
             down and the monitored process was terminated. Start a new run after unlocking."
        );
        // Non-zero: the run did not complete on the child's own terms.
        std::process::exit(125);
    }
    eprintln!(
        "Monitored session {short} finished — runtime={} ({}), requests={}, errors={}{}.",
        outcome.assessment.runtime,
        outcome.assessment.trust_level,
        session.request_count,
        session.error_count,
        if session.partial_coverage {
            " — PARTIAL coverage: some traffic bypassed monitoring (see `observe show`)"
        } else {
            ""
        }
    );
    std::process::exit(outcome.exit_code.unwrap_or(1));
}

/// The credential ids that will be injected (explicit selectors, or the
/// project's env mappings when none are given).
fn resolve_credential_ids(
    vault: &api_tracker_core::vault::UnlockedVault,
    project: &str,
    explicit: &[(String, String)],
) -> Result<Vec<String>> {
    if explicit.is_empty() {
        Ok(vault
            .list_env_mappings(project)?
            .into_iter()
            .map(|m| m.credential_id)
            .collect())
    } else {
        let mut ids = Vec::new();
        for (selector, _env) in explicit {
            ids.push(vault.get_credential(selector)?.id);
        }
        Ok(ids)
    }
}

fn describe_status(status: &std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        format!("exited with code {code}")
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = status.signal() {
                return format!("was terminated by signal {sig}");
            }
        }
        "exited abnormally".to_string()
    }
}
