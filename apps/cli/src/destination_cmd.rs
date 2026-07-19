//! `api-tracker destination` — configure and inspect secret destinations.
//!
//! Destination administrative credentials are read from stdin, a hidden
//! prompt, or `API_TRACKER_DESTINATION_AUTH`; they are stored encrypted and
//! are write-only afterwards. Nothing here prints a secret.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Context, Result};
use api_tracker_core::destinations;
use api_tracker_core::secret::SecretString;
use clap::{Args, Subcommand};
use std::io::Read;

pub const ENV_DESTINATION_AUTH: &str = "API_TRACKER_DESTINATION_AUTH";

#[derive(Subcommand)]
pub enum DestinationCmd {
    /// Show every destination kind and its honest capability matrix.
    Kinds,
    /// List configured destinations.
    List,
    /// Configure a destination (auth via --auth-stdin, env, or prompt).
    Add(AddArgs),
    /// Remove a destination (reauthentication required).
    Remove(RemoveArgs),
    /// Verify a destination's authentication/reachability.
    Test(TestArgs),
    /// Attach a credential to a destination under a secret name.
    Attach(AttachArgs),
    /// Detach a credential from a destination.
    Detach(DetachArgs),
    /// List credential↔destination attachments and their drift state.
    Attachments(AttachmentsArgs),
    /// Check every attachment for drift against the destination.
    Drift(AttachmentsArgs),
    /// Delete a secret AT the destination (destructive; reauthenticated).
    DeleteSecret(DeleteSecretArgs),
}

#[derive(Args)]
pub struct DeleteSecretArgs {
    /// The configured destination (name or id).
    pub destination: String,
    /// The secret name at the destination.
    pub secret_name: String,
    /// Skip the interactive confirmation.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct AddArgs {
    /// Destination kind (see `destination kinds`).
    pub kind: String,
    /// A name of your choice for this destination.
    #[arg(long)]
    pub name: String,
    /// AWS region (aws_secrets_manager).
    #[arg(long)]
    pub region: Option<String>,
    /// Repository owner (github_actions).
    #[arg(long)]
    pub owner: Option<String>,
    /// Repository name (github_actions).
    #[arg(long)]
    pub repo: Option<String>,
    /// Vercel project id (vercel).
    #[arg(long)]
    pub project_id: Option<String>,
    /// Vercel team id (vercel, optional).
    #[arg(long)]
    pub team_id: Option<String>,
    /// Vercel targets, comma-separated (default production,preview,development).
    #[arg(long)]
    pub targets: Option<String>,
    /// Keychain account label (macos_keychain, default api-tracker).
    #[arg(long)]
    pub account: Option<String>,
    /// Read the destination credential from stdin.
    #[arg(long)]
    pub auth_stdin: bool,
    /// This destination needs no stored credential (macos_keychain).
    #[arg(long)]
    pub no_auth: bool,
    /// Skip the connection test after storing.
    #[arg(long)]
    pub no_verify: bool,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Destination name or id.
    pub destination: String,
    /// Confirm non-interactively.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct TestArgs {
    /// Destination name or id.
    pub destination: String,
}

#[derive(Args)]
pub struct AttachArgs {
    /// Credential selector (project/name or id).
    pub credential: String,
    /// Destination name or id.
    pub destination: String,
    /// The name the secret has AT the destination.
    #[arg(long)]
    pub secret_name: String,
    /// Environment label for this deployment (e.g. production).
    #[arg(long, default_value = "")]
    pub environment: String,
}

#[derive(Args)]
pub struct DetachArgs {
    /// Credential selector.
    pub credential: String,
    /// Destination name or id.
    pub destination: String,
    /// Only this secret name (default: every attachment to the destination).
    #[arg(long)]
    pub secret_name: Option<String>,
}

#[derive(Args)]
pub struct AttachmentsArgs {
    /// Limit to one credential.
    #[arg(long)]
    pub credential: Option<String>,
}

fn destination_auth(auth_stdin: bool) -> Result<SecretString> {
    if auth_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read the destination credential from stdin")?;
        let value = SecretString::new(buf.trim_end_matches(['\n', '\r']).to_owned());
        if value.expose().trim().is_empty() {
            bail!("no destination credential was provided on stdin");
        }
        return Ok(value);
    }
    if std::env::var_os(ENV_DESTINATION_AUTH).is_some() {
        return Ok(SecretString::new(
            std::env::var(ENV_DESTINATION_AUTH)
                .context("API_TRACKER_DESTINATION_AUTH is not valid UTF-8")?,
        ));
    }
    ctx::prompt_secret("Destination credential (hidden)")
}

pub fn run(ctx: &Ctx, cmd: DestinationCmd) -> Result<()> {
    match cmd {
        DestinationCmd::Kinds => kinds(ctx),
        DestinationCmd::List => list(ctx),
        DestinationCmd::Add(args) => add(ctx, args),
        DestinationCmd::Remove(args) => remove(ctx, args),
        DestinationCmd::Test(args) => test(ctx, args),
        DestinationCmd::Attach(args) => attach(ctx, args),
        DestinationCmd::Detach(args) => detach(ctx, args),
        DestinationCmd::Attachments(args) => attachments(ctx, args, false),
        DestinationCmd::Drift(args) => attachments(ctx, args, true),
        DestinationCmd::DeleteSecret(args) => delete_secret(ctx, args),
    }
}

fn delete_secret(ctx: &Ctx, args: DeleteSecretArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let dest = vault.destination_get(&args.destination)?;
    println!(
        "This deletes secret '{}' AT destination '{}' ({}).",
        args.secret_name, dest.name, dest.kind
    );
    if dest.kind == "aws_secrets_manager" {
        println!(
            "AWS schedules deletion with a 30-day recovery window; RestoreSecret can cancel \
             it until the deletion date."
        );
    } else {
        println!("Deletion at this destination is immediate.");
    }
    println!("The value in the local vault is NOT touched.");
    if !ctx::confirm("Delete the secret at the destination?", args.yes)? {
        println!("cancelled");
        return Ok(());
    }
    eprintln!("Reauthentication required to delete at a destination.");
    let password = ctx::master_password()?;
    let http = api_tracker_core::http::UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    let detail = vault.destination_delete_secret(
        &args.destination,
        &args.secret_name,
        &password,
        &http,
        &runner,
    )?;
    println!("{detail}");
    Ok(())
}

fn support_label(s: destinations::DestSupport) -> &'static str {
    match s {
        destinations::DestSupport::Implemented => "yes",
        destinations::DestSupport::SupportedNotImplemented => "not impl.",
        destinations::DestSupport::Unsupported => "no",
        destinations::DestSupport::PlatformUnavailable => "n/a here",
    }
}

fn kinds(ctx: &Ctx) -> Result<()> {
    let catalog = destinations::catalog();
    render::emit(ctx.json, &catalog, || {
        let rows: Vec<Vec<String>> = catalog
            .iter()
            .map(|k| {
                vec![
                    k.kind.to_string(),
                    support_label(k.capabilities.read).into(),
                    support_label(k.capabilities.write).into(),
                    support_label(k.capabilities.delete).into(),
                    support_label(k.capabilities.versioning).into(),
                    support_label(k.capabilities.rollback).into(),
                    support_label(k.capabilities.validation).into(),
                    k.platforms.to_string(),
                ]
            })
            .collect();
        render::table(
            &[
                "KIND",
                "READ",
                "WRITE",
                "DELETE",
                "VERSIONS",
                "ROLLBACK",
                "VALIDATE",
                "PLATFORMS",
            ],
            &rows,
        );
        println!();
        for k in catalog {
            println!("{} — {}", k.kind, k.name);
            println!("  {}", k.description);
            println!("  Auth:     {}", k.auth);
            println!("  Status:   {}", k.status);
            println!("  Verify:   {}", k.verify_method);
            println!("  Plan:     {}", k.required_plan);
            println!("  Charges:  {}", k.charges);
            println!("  Testing:  {}", k.testing);
            println!("  Config:   {}", k.config_help);
        }
    });
    Ok(())
}

fn list(ctx: &Ctx) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let dests = vault.destination_list()?;
    render::emit(ctx.json, &dests, || {
        if dests.is_empty() {
            println!(
                "No destinations configured. Add one with `destination add <kind> --name <n>`."
            );
            return;
        }
        let rows: Vec<Vec<String>> = dests
            .iter()
            .map(|d| {
                vec![
                    d.name.clone(),
                    d.kind.clone(),
                    d.auth_masked.clone().unwrap_or_else(|| "(none)".into()),
                    d.last_verified_at.clone().unwrap_or_else(|| "never".into()),
                    if d.last_error.is_empty() {
                        "-".into()
                    } else {
                        d.last_error.clone()
                    },
                ]
            })
            .collect();
        render::table(&["NAME", "KIND", "AUTH", "VERIFIED", "LAST ERROR"], &rows);
    });
    Ok(())
}

fn add(ctx: &Ctx, args: AddArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let mut config = serde_json::Map::new();
    let mut put = |key: &str, value: &Option<String>| {
        if let Some(v) = value {
            config.insert(key.to_string(), serde_json::Value::String(v.clone()));
        }
    };
    put("region", &args.region);
    put("owner", &args.owner);
    put("repo", &args.repo);
    put("project_id", &args.project_id);
    put("team_id", &args.team_id);
    put("account", &args.account);
    if let Some(targets) = &args.targets {
        config.insert(
            "targets".into(),
            serde_json::Value::Array(
                targets
                    .split(',')
                    .map(|t| serde_json::Value::String(t.trim().to_string()))
                    .collect(),
            ),
        );
    }
    let needs_auth = args.kind != "macos_keychain" && !args.no_auth;
    let auth = if needs_auth {
        if args.kind == "aws_secrets_manager" {
            eprintln!(
                "Provide the AWS credential as JSON: \
                 {{\"access_key_id\":\"...\",\"secret_access_key\":\"...\"}}"
            );
        }
        Some(destination_auth(args.auth_stdin)?)
    } else {
        None
    };
    let dest = vault.destination_add(
        &args.kind,
        &args.name,
        serde_json::Value::Object(config),
        auth.as_ref(),
    )?;
    println!("Configured destination '{}' ({}).", dest.name, dest.kind);
    if !args.no_verify {
        let http = api_tracker_core::http::UreqClient::new();
        let runner = destinations::SystemRunner;
        match vault.destination_test(&dest.id, &http, &runner) {
            Ok(detail) => println!("Verified: {detail}"),
            Err(e) => println!(
                "WARNING: verification failed ({e}). The destination is stored; fix the \
                 problem and run `destination test {}`.",
                dest.name
            ),
        }
    }
    Ok(())
}

fn remove(ctx: &Ctx, args: RemoveArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    if !ctx::confirm(
        &format!(
            "Remove destination '{}'? Its stored credential and attachment records are deleted \
             (nothing is changed AT the destination).",
            args.destination
        ),
        args.yes,
    )? {
        bail!("cancelled");
    }
    let password = ctx::master_password()?;
    let dest = vault.destination_remove(&args.destination, &password)?;
    println!("Removed destination '{}'.", dest.name);
    Ok(())
}

fn test(ctx: &Ctx, args: TestArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let http = api_tracker_core::http::UreqClient::new();
    let runner = destinations::SystemRunner;
    let detail = vault.destination_test(&args.destination, &http, &runner)?;
    println!("OK: {detail}");
    Ok(())
}

fn attach(ctx: &Ctx, args: AttachArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    vault.destination_attach(
        &args.credential,
        &args.destination,
        &args.secret_name,
        &args.environment,
    )?;
    println!(
        "Attached: '{}' deploys to '{}' as '{}'. Generate a plan with \
         `sync plan {}` when the value changes.",
        args.credential, args.destination, args.secret_name, args.credential
    );
    Ok(())
}

fn detach(ctx: &Ctx, args: DetachArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let n = vault.destination_detach(
        &args.credential,
        &args.destination,
        args.secret_name.as_deref(),
    )?;
    println!("Removed {n} attachment(s). Nothing was changed AT the destination.");
    Ok(())
}

fn attachments(ctx: &Ctx, args: AttachmentsArgs, check_drift: bool) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    if check_drift {
        let http = api_tracker_core::http::UreqClient::new();
        let runner = destinations::SystemRunner;
        let outcomes = vault.destination_drift_check(args.credential.as_deref(), &http, &runner)?;
        render::emit(ctx.json, &outcomes, || {
            if outcomes.is_empty() {
                println!("No attachments. Create one with `destination attach`.");
                return;
            }
            let rows: Vec<Vec<String>> = outcomes
                .iter()
                .map(|o| {
                    let a = &o.attachment;
                    vec![
                        format!("{}/{}", a.project_name, a.credential_name),
                        a.destination_name.clone(),
                        a.secret_name.clone(),
                        if a.environment.is_empty() {
                            "-".into()
                        } else {
                            a.environment.clone()
                        },
                        a.last_synced_version
                            .map(|v| format!("v{v}"))
                            .unwrap_or_else(|| "never".into()),
                        // Never present a skipped attachment's stored drift as
                        // a fresh result (DEST-03).
                        if o.checked {
                            a.drift.clone()
                        } else {
                            format!(
                                "not checked ({})",
                                o.check_error.as_deref().unwrap_or("skipped")
                            )
                        },
                    ]
                })
                .collect();
            render::table(
                &[
                    "CREDENTIAL",
                    "DESTINATION",
                    "SECRET",
                    "ENV",
                    "SYNCED",
                    "DRIFT",
                ],
                &rows,
            );
        });
        return Ok(());
    }
    let attachments = vault.destination_attachments(args.credential.as_deref())?;
    render::emit(ctx.json, &attachments, || {
        if attachments.is_empty() {
            println!("No attachments. Create one with `destination attach`.");
            return;
        }
        let rows: Vec<Vec<String>> = attachments
            .iter()
            .map(|a| {
                vec![
                    format!("{}/{}", a.project_name, a.credential_name),
                    a.destination_name.clone(),
                    a.secret_name.clone(),
                    if a.environment.is_empty() {
                        "-".into()
                    } else {
                        a.environment.clone()
                    },
                    a.last_synced_version
                        .map(|v| format!("v{v}"))
                        .unwrap_or_else(|| "never".into()),
                    a.drift.clone(),
                ]
            })
            .collect();
        render::table(
            &[
                "CREDENTIAL",
                "DESTINATION",
                "SECRET NAME",
                "ENV",
                "SYNCED",
                "DRIFT",
            ],
            &rows,
        );
    });
    Ok(())
}
