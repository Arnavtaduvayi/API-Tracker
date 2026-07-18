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
    #[arg(long)]
    pub project: String,
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
    let (env, session) = vault.build_injection(&args.project, &explicit, &command_label)?;

    let injected_names: Vec<&str> = env.iter().map(|(v, _)| v.as_str()).collect();
    eprintln!(
        "Injecting {} credential(s) into the environment: {}",
        env.len(),
        injected_names.join(", ")
    );

    let program = &args.command[0];
    let mut cmd = std::process::Command::new(program);
    cmd.args(&args.command[1..]);
    for (name, value) in &env {
        // The secret is set on the child's environment only.
        cmd.env(name, value.expose());
    }

    let status = cmd.status();
    // env (with its SecretStrings) drops here, zeroizing the values.
    drop(env);

    let (code, summary): (Option<i32>, String) = match status {
        Ok(s) => (s.code(), describe_status(&s)),
        Err(e) => {
            let _ = vault.end_process_session(&session, None);
            bail!("failed to run '{program}': {e}");
        }
    };
    vault.end_process_session(&session, code)?;
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
