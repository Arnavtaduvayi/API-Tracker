//! `project` subcommands.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::model::Environment;
use api_tracker_core::vault::{NewProject, UpdateProject};
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum ProjectCmd {
    /// Create a project.
    Create(CreateArgs),
    /// List projects.
    List {
        /// Include archived projects.
        #[arg(long)]
        archived: bool,
    },
    /// Show one project.
    Show { project: String },
    /// Edit project metadata, environments, and repository paths.
    Edit(EditArgs),
    /// Archive a project (hidden from default listings; nothing is deleted).
    Archive { project: String },
    /// Restore an archived project.
    Restore { project: String },
    /// Password-lock a project. First use sets the project password; later
    /// uses drop its key from the current session.
    Lock { project: String },
    /// Unlock a password-locked project for this session.
    Unlock { project: String },
}

#[derive(Args)]
pub struct CreateArgs {
    /// Project name (unique).
    pub name: String,
    #[arg(long, default_value = "")]
    pub description: String,
    /// Environment classifications (repeatable): development, test, staging,
    /// production.
    #[arg(long = "env", value_name = "ENVIRONMENT")]
    pub environments: Vec<String>,
    /// Local repository paths (repeatable).
    #[arg(long = "repo", value_name = "PATH")]
    pub repos: Vec<String>,
    #[arg(long, default_value = "")]
    pub notes: String,
}

#[derive(Args)]
pub struct EditArgs {
    pub project: String,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub description: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
    /// Replace the environment classifications (repeatable).
    #[arg(long = "env", value_name = "ENVIRONMENT")]
    pub environments: Option<Vec<String>>,
    #[arg(long = "add-repo", value_name = "PATH")]
    pub add_repos: Vec<String>,
    #[arg(long = "remove-repo", value_name = "PATH")]
    pub remove_repos: Vec<String>,
    /// Remove the project password lock (asks for the current project
    /// password).
    #[arg(long)]
    pub remove_password: bool,
}

fn parse_envs(raw: &[String]) -> Result<Vec<Environment>> {
    raw.iter().map(|s| Ok(s.parse::<Environment>()?)).collect()
}

/// Unlocking/locking a project only persists via a session token; in
/// per-command password mode the state would evaporate on exit, so refuse
/// with clear guidance instead of claiming success.
fn require_session(token: &Option<api_tracker_core::session::SessionToken>) -> Result<()> {
    if token.is_none() {
        bail!(
            "this changes per-session project state, which requires an active session. \
             Run `tethra unlock`, export TETHRA_SESSION (legacy \
             API_TRACKER_SESSION also works), then retry (it does not work \
             with TETHRA_PASSWORD/API_TRACKER_PASSWORD alone)."
        );
    }
    Ok(())
}

pub fn run(ctx: &Ctx, cmd: ProjectCmd) -> Result<()> {
    match cmd {
        ProjectCmd::Create(args) => {
            let (mut vault, _token) = ctx.unlocked()?;
            let project = vault.create_project(NewProject {
                name: args.name,
                description: args.description,
                notes: args.notes,
                environments: parse_envs(&args.environments)?,
                repo_paths: args.repos,
            })?;
            for repo in &project.repo_paths {
                if !std::path::Path::new(repo).exists() {
                    eprintln!("note: repository path '{repo}' does not currently exist");
                }
            }
            render::emit(ctx.json, &project, || {
                println!("Created project '{}'", project.name);
            });
        }
        ProjectCmd::List { archived } => {
            let (vault, _token) = ctx.unlocked()?;
            let projects = vault.list_projects(archived)?;
            render::emit(ctx.json, &projects, || {
                if projects.is_empty() {
                    println!("No projects yet. Create one with `tethra project create <name>`.");
                } else {
                    render::table(
                        &["NAME", "ENVIRONMENTS", "KEYS", "STATE", "DESCRIPTION"],
                        &render::project_rows(&projects),
                    );
                }
            });
        }
        ProjectCmd::Show { project } => {
            let (vault, _token) = ctx.unlocked()?;
            let project = vault.get_project(&project)?;
            render::emit(ctx.json, &project, || render::print_project(&project));
        }
        ProjectCmd::Edit(args) => {
            let (mut vault, token) = ctx.unlocked()?;
            if args.remove_password {
                let password = ctx::project_password()?;
                vault.remove_project_password(&args.project, &password)?;
                ctx.persist_session(&vault, &token)?;
                println!("Project password removed; the vault lock still protects the project.");
            }
            let environments = match &args.environments {
                Some(raw) => Some(parse_envs(raw)?),
                None => None,
            };
            let project = vault.update_project(
                &args.project,
                UpdateProject {
                    name: args.name,
                    description: args.description,
                    notes: args.notes,
                    environments,
                    add_repo_paths: args.add_repos,
                    remove_repo_paths: args.remove_repos,
                },
            )?;
            render::emit(ctx.json, &project, || {
                println!("Updated project '{}'", project.name);
            });
        }
        ProjectCmd::Archive { project } => {
            let (mut vault, _token) = ctx.unlocked()?;
            let project = vault.set_project_archived(&project, true)?;
            println!(
                "Archived project '{}' (restore with `project restore`).",
                project.name
            );
        }
        ProjectCmd::Restore { project } => {
            let (mut vault, _token) = ctx.unlocked()?;
            let project = vault.set_project_archived(&project, false)?;
            println!("Restored project '{}'.", project.name);
        }
        ProjectCmd::Lock { project } => {
            let (mut vault, token) = ctx.unlocked()?;
            let current = vault.get_project(&project)?;
            if !current.password_locked {
                eprintln!(
                    "Setting a project password for '{}'. You will need it (in addition to \
                     the master password) to use this project's credentials.",
                    current.name
                );
                eprintln!("If you lose it, this project's credential values are unrecoverable.");
                let password = ctx::new_password("project password", ctx::ENV_PROJECT_PASSWORD)?;
                eprintln!("Reauthentication required to set a project password.");
                let master = ctx::master_password()?;
                vault.set_project_password(&project, &password, &master)?;
                // Immediately lock so the password takes effect now.
                vault.lock_project(&project)?;
                ctx.persist_session(&vault, &token)?;
                println!("Project '{}' is now password-locked.", current.name);
            } else {
                require_session(&token)?;
                vault.lock_project(&project)?;
                ctx.persist_session(&vault, &token)?;
                println!("Project '{}' locked for this session.", current.name);
            }
        }
        ProjectCmd::Unlock { project } => {
            let (mut vault, token) = ctx.unlocked()?;
            let current = vault.get_project(&project)?;
            if !current.password_locked {
                bail!(
                    "project '{}' has no password lock (the vault lock already protects it)",
                    current.name
                );
            }
            require_session(&token)?;
            let password = ctx::project_password()?;
            let project = vault.unlock_project(&project, &password)?;
            ctx.persist_session(&vault, &token)?;
            println!("Project '{}' unlocked for this session.", project.name);
        }
    }
    Ok(())
}
