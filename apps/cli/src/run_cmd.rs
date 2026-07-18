//! `api-tracker run` — secure process injection.
//!
//! Decrypts only the selected credentials of one project and injects them
//! into the child process's environment. Values are never written to disk,
//! never printed, and unrelated project credentials are never injected. The
//! child inherits the parent environment plus the injected variables; when it
//! exits the values are gone (the child's environment dies with it and the
//! in-process `SecretString` buffers are zeroized on drop).

use crate::ctx::Ctx;
use anyhow::{bail, Result};
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
    /// The command to run, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
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

    let (vault, _token) = ctx.unlocked()?;
    let command_label = args.command.join(" ");
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
    // Do NOT leak API Tracker's own secret environment (the master password
    // or session token) into the child. It inherits the rest of the parent
    // environment plus only the credentials we inject.
    for var in [
        crate::ctx::ENV_PASSWORD,
        crate::ctx::ENV_SESSION,
        crate::ctx::ENV_PROJECT_PASSWORD,
        crate::ctx::ENV_BACKUP_PASSWORD,
        crate::ctx::ENV_PROVIDER_ADMIN_KEY,
        crate::destination_cmd::ENV_DESTINATION_AUTH,
    ] {
        cmd.env_remove(var);
    }
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
                        let _ = vault.end_process_session(&session, None);
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
