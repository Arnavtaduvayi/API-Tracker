//! `key` subcommands. Output always redacts values; `key reveal` is the
//! single deliberate exception and requires reauthentication.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::model::Environment;
use api_tracker_core::vault::{AddCredential, AddReference, UpdateCredential};
use clap::{Args, Subcommand};
use std::io::IsTerminal;

#[derive(Subcommand)]
pub enum KeyCmd {
    /// Add a credential to a project.
    Add(AddArgs),
    /// List credentials (optionally for one project).
    List {
        #[arg(long)]
        project: Option<String>,
    },
    /// Show one credential (masked).
    Show { key: String },
    /// Show a credential's full status report with reasons and evidence.
    Status { key: String },
    /// Reveal a credential value (requires the master password again).
    Reveal { key: String },
    /// Update credential metadata, value, or manual status marks.
    Update(Box<UpdateArgs>),
    /// Delete a credential (asks for confirmation).
    Remove {
        key: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Validate a credential against its provider (network request).
    Validate { key: String },
    /// Fetch provider-side metadata for a credential (network request).
    Metadata { key: String },
    /// Show (and optionally sync) a credential's permissions.
    Permissions {
        key: String,
        /// Fetch permissions from the provider now (network request).
        #[arg(long)]
        sync: bool,
    },
    /// Show a credential's retained value versions (masked; reauth).
    Versions { key: String },
}

#[derive(Args)]
pub struct AddArgs {
    /// Project to add the credential to.
    #[arg(long)]
    pub project: String,
    /// Friendly name (unique within the project).
    #[arg(long)]
    pub name: String,
    /// Provider id (see `api-tracker provider list`) or any custom name.
    #[arg(long, default_value = "other")]
    pub provider: String,
    /// development, test, staging, or production.
    #[arg(long, default_value = "development")]
    pub environment: String,
    /// Read the secret value from stdin instead of an interactive prompt.
    /// (The value is never accepted as a command-line argument.)
    #[arg(long)]
    pub value_stdin: bool,
    /// Date the key was created at the provider (YYYY-MM-DD).
    #[arg(long, value_name = "DATE")]
    pub key_created: Option<String>,
    /// Expiration date (YYYY-MM-DD).
    #[arg(long, value_name = "DATE")]
    pub expires: Option<String>,
    #[arg(long, default_value = "")]
    pub docs_url: String,
    #[arg(long, default_value = "")]
    pub notes: String,
    /// Store a duplicate copy even if the same value already exists in the
    /// vault.
    #[arg(long)]
    pub allow_duplicate: bool,
    /// Instead of storing a value, reference an existing credential
    /// (project/name or id). No secret is duplicated.
    #[arg(long, value_name = "CREDENTIAL", conflicts_with = "value_stdin")]
    pub link_to: Option<String>,
}

#[derive(Args)]
pub struct UpdateArgs {
    pub key: String,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub provider: Option<String>,
    #[arg(long)]
    pub environment: Option<String>,
    /// New key-creation date (YYYY-MM-DD), or 'none' to clear.
    #[arg(long, value_name = "DATE")]
    pub key_created: Option<String>,
    /// New expiration date (YYYY-MM-DD), or 'none' to clear.
    #[arg(long, value_name = "DATE")]
    pub expires: Option<String>,
    #[arg(long)]
    pub docs_url: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
    /// Replace the secret value (prompts; requires the master password).
    #[arg(long)]
    pub new_value: bool,
    /// With --new-value: read the new value from stdin.
    #[arg(long, requires = "new_value")]
    pub value_stdin: bool,
    /// Record that the credential was just used.
    #[arg(long)]
    pub mark_used_now: bool,
    /// Record a successful manual validation.
    #[arg(long, conflicts_with = "mark_invalid")]
    pub mark_valid: bool,
    /// Record a failed manual validation (marks the credential invalid).
    #[arg(long)]
    pub mark_invalid: bool,
    #[arg(long, conflicts_with = "enable")]
    pub disable: bool,
    #[arg(long)]
    pub enable: bool,
    /// Mark as revoked at the provider.
    #[arg(long, conflicts_with = "unrevoke")]
    pub revoke: bool,
    #[arg(long)]
    pub unrevoke: bool,
    /// Flag as possibly exposed, with an optional note explaining where.
    #[arg(long, value_name = "NOTE", num_args = 0..=1, default_missing_value = "",
          conflicts_with = "clear_exposed")]
    pub possibly_exposed: Option<String>,
    #[arg(long)]
    pub clear_exposed: bool,
}

fn optional_date(raw: Option<String>) -> Option<Option<String>> {
    raw.map(|s| {
        if s.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(s)
        }
    })
}

pub fn run(ctx: &Ctx, cmd: KeyCmd) -> Result<()> {
    match cmd {
        KeyCmd::Add(args) => add(ctx, args),
        KeyCmd::Versions { key } => versions(ctx, &key),
        KeyCmd::List { project } => {
            let (vault, _token) = ctx.unlocked()?;
            let credentials = vault.list_credentials(project.as_deref())?;
            render::emit(ctx.json, &credentials, || {
                if credentials.is_empty() {
                    println!("No credentials found.");
                } else {
                    render::table(
                        &["CREDENTIAL", "PROVIDER", "ENV", "VALUE", "STATUS"],
                        &render::credential_rows(&credentials),
                    );
                }
            });
            Ok(())
        }
        KeyCmd::Show { key } => {
            let (vault, _token) = ctx.unlocked()?;
            let credential = vault.get_credential(&key)?;
            render::emit(ctx.json, &credential, || {
                render::print_credential(&credential)
            });
            Ok(())
        }
        KeyCmd::Status { key } => {
            let (vault, _token) = ctx.unlocked()?;
            let credential = vault.get_credential(&key)?;
            render::emit(ctx.json, &credential.status, || {
                println!(
                    "Credential: {}/{}",
                    credential.project_name, credential.name
                );
                render::print_status_report(&credential.status);
            });
            Ok(())
        }
        KeyCmd::Reveal { key } => {
            let (mut vault, _token) = ctx.unlocked()?;
            eprintln!("Reauthentication required to reveal a credential value.");
            let password = ctx::master_password()?;
            let value = vault.reveal_credential(&key, &password)?;
            // The one deliberate plaintext output in the whole CLI.
            println!("{}", value.expose());
            eprintln!("WARNING: the value above was printed to this terminal.");
            Ok(())
        }
        KeyCmd::Update(args) => update(ctx, *args),
        KeyCmd::Remove { key, yes } => {
            let (mut vault, _token) = ctx.unlocked()?;
            let credential = vault.get_credential(&key)?;
            let label = format!("{}/{}", credential.project_name, credential.name);
            if !ctx::confirm(
                &format!("Delete credential '{label}'? This cannot be undone."),
                yes,
            )? {
                bail!("aborted");
            }
            vault.delete_credential(&credential.id)?;
            println!("Deleted credential '{label}'.");
            Ok(())
        }
        KeyCmd::Validate { key } => {
            let (mut vault, _token) = ctx.unlocked()?;
            let http = api_tracker_core::http::UreqClient::new();
            let result = vault.validate_credential(&key, &http)?;
            render::emit(ctx.json, &result, || {
                println!(
                    "{}: {}",
                    if result.valid { "VALID" } else { "INVALID" },
                    result.detail
                );
            });
            Ok(())
        }
        KeyCmd::Metadata { key } => {
            let (vault, _token) = ctx.unlocked()?;
            let http = api_tracker_core::http::UreqClient::new();
            let meta = vault.fetch_metadata(&key, &http)?;
            render::emit(ctx.json, &meta, || {
                println!("Provider metadata ({}):", meta.source);
                for (k, v) in &meta.fields {
                    println!("  {k}: {v}");
                }
            });
            Ok(())
        }
        KeyCmd::Permissions { key, sync } => {
            let (vault, _token) = ctx.unlocked()?;
            let stored = if sync {
                let http = api_tracker_core::http::UreqClient::new();
                Some(vault.sync_permissions(&key, &http)?)
            } else {
                vault.get_permissions(&key)?
            };
            match stored {
                Some(p) => render::emit(ctx.json, &p, || render::print_permissions(&p)),
                None => println!("No permissions synced yet. Re-run with --sync."),
            }
            Ok(())
        }
    }
}

fn add(ctx: &Ctx, args: AddArgs) -> Result<()> {
    let (mut vault, _token) = ctx.unlocked()?;
    let environment: Environment = args.environment.parse()?;

    if let Some(source) = args.link_to {
        // A reference inherits its provider, type, dates, and value from the
        // source. Reject flags that would be silently ignored so the user is
        // not misled into thinking they applied.
        let ignored = [
            ("--provider", args.provider != "other"),
            ("--environment", false), // environment does apply to references
            ("--key-created", args.key_created.is_some()),
            ("--expires", args.expires.is_some()),
            ("--allow-duplicate", args.allow_duplicate),
        ];
        let offenders: Vec<&str> = ignored
            .iter()
            .filter(|(_, set)| *set)
            .map(|(name, _)| *name)
            .collect();
        if !offenders.is_empty() {
            bail!(
                "these flags do not apply to a reference (a reference inherits them from its \
                 source): {}. Remove them, or omit --link-to to store a separate credential.",
                offenders.join(", ")
            );
        }
        let credential = vault.add_credential_reference(AddReference {
            project: args.project,
            source,
            name: args.name,
            environment,
            docs_url: args.docs_url,
            notes: args.notes,
        })?;
        render::emit(ctx.json, &credential, || {
            println!(
                "Added '{}/{}' as a reference to {} (no secret value was duplicated).",
                credential.project_name,
                credential.name,
                credential.linked_target.as_deref().unwrap_or("?")
            );
        });
        return Ok(());
    }

    let value = ctx::credential_value(args.value_stdin)?;
    let warnings = vault.check_reuse(&args.project, environment, &value)?;
    if !warnings.is_empty() {
        render::print_reuse_warnings(&warnings);
        if !args.allow_duplicate {
            let interactive = std::io::stdin().is_terminal();
            if interactive {
                if !ctx::confirm("Store a duplicate copy of this value anyway?", false)? {
                    bail!(
                        "aborted. Use `--link-to <credential>` to reference the existing \
                         entry instead of storing a copy"
                    );
                }
            } else {
                bail!(
                    "this value already exists in the vault (see warnings above). \
                     Re-run with --allow-duplicate to store a copy, or --link-to \
                     <credential> to reference the existing entry"
                );
            }
        }
    }

    let (credential, _) = vault.add_credential(AddCredential {
        project: args.project,
        provider: args.provider,
        name: args.name,
        environment,
        value,
        credential_type: None,
        key_created_at: args.key_created,
        expires_at: args.expires,
        docs_url: args.docs_url,
        notes: args.notes,
    })?;
    render::emit(ctx.json, &credential, || {
        println!(
            "Added credential '{}/{}' ({}, {}).",
            credential.project_name, credential.name, credential.provider, credential.environment
        );
        println!(
            "Stored value: {} (encrypted at rest)",
            credential.masked_value
        );
    });
    Ok(())
}

fn versions(ctx: &Ctx, key: &str) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    eprintln!("Reauthentication required to view version history.");
    let password = ctx::master_password()?;
    let history = vault.credential_version_history(key, &password)?;
    render::emit(ctx.json, &history, || {
        let rows: Vec<Vec<String>> = history
            .iter()
            .map(|v| {
                vec![
                    format!("v{}", v.version),
                    v.masked_value.clone(),
                    v.created_at.clone(),
                    if v.current {
                        "current".into()
                    } else {
                        v.reason.clone()
                    },
                ]
            })
            .collect();
        render::table(&["VERSION", "VALUE (MASKED)", "AT", "NOTE"], &rows);
        println!(
            "\nOld versions exist so destination rollback works (`sync rollback`); they are \
             encrypted like current values and pruned automatically."
        );
    });
    Ok(())
}

fn update(ctx: &Ctx, args: UpdateArgs) -> Result<()> {
    let (mut vault, _token) = ctx.unlocked()?;

    if args.new_value {
        eprintln!("Reauthentication required to replace a credential value.");
        let password = ctx::master_password()?;
        let value = ctx::credential_value(args.value_stdin)?;
        let (credential, warnings) = vault.replace_credential_value(&args.key, &password, value)?;
        render::print_reuse_warnings(&warnings);
        println!(
            "Replaced the value of '{}/{}' (now {}).",
            credential.project_name, credential.name, credential.masked_value
        );
    }

    let environment = match &args.environment {
        Some(raw) => Some(raw.parse::<Environment>()?),
        None => None,
    };
    let update = UpdateCredential {
        name: args.name,
        provider: args.provider,
        environment,
        key_created_at: optional_date(args.key_created),
        expires_at: optional_date(args.expires),
        docs_url: args.docs_url,
        notes: args.notes,
        mark_used_now: args.mark_used_now,
        mark_validated: if args.mark_valid {
            Some(true)
        } else if args.mark_invalid {
            Some(false)
        } else {
            None
        },
        disabled: if args.disable {
            Some(true)
        } else if args.enable {
            Some(false)
        } else {
            None
        },
        revoked: if args.revoke {
            Some(true)
        } else if args.unrevoke {
            Some(false)
        } else {
            None
        },
        possibly_exposed: if args.possibly_exposed.is_some() {
            Some(true)
        } else if args.clear_exposed {
            Some(false)
        } else {
            None
        },
        exposure_note: args.possibly_exposed.clone(),
    };
    let credential = vault.update_credential(&args.key, update)?;
    render::emit(ctx.json, &credential, || {
        println!(
            "Updated '{}/{}' (status: {}).",
            credential.project_name, credential.name, credential.status.primary
        );
    });
    Ok(())
}
