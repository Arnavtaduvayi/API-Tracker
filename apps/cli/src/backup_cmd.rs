//! `backup` subcommands: encrypted create, verify, restore.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::backup;
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum BackupCmd {
    /// Create an encrypted backup file (requires reauthentication).
    Create {
        path: PathBuf,
        /// Overwrite the file if it already exists.
        #[arg(long)]
        overwrite: bool,
    },
    /// Decrypt and validate a backup without restoring it.
    Verify { path: PathBuf },
    /// Restore a backup into the data directory.
    Restore {
        path: PathBuf,
        /// Replace an existing vault (the old database is renamed aside,
        /// not deleted).
        #[arg(long)]
        force: bool,
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(ctx: &Ctx, cmd: BackupCmd) -> Result<()> {
    match cmd {
        BackupCmd::Create { path, overwrite } => {
            let (vault, _token) = ctx.unlocked()?;
            eprintln!("Reauthentication required to export a backup.");
            let master = ctx::master_password()?;
            vault.verify_master_password(&master)?;
            eprintln!(
                "Choose a backup password. It protects this file and is required to restore."
            );
            let backup_pw = ctx::backup_password(true)?;
            let info = backup::create_backup(&vault, &path, &backup_pw, overwrite)?;
            render::emit(ctx.json, &info, || {
                println!(
                    "Backup written to {} ({} project(s), {} credential(s)).",
                    info.path, info.project_count, info.credential_count
                );
                println!(
                    "Restoring requires BOTH the backup password and the master password \
                     from the time of this backup."
                );
            });
        }
        BackupCmd::Verify { path } => {
            let backup_pw = ctx::backup_password(false)?;
            let info = backup::verify_backup(&path, &backup_pw)?;
            render::emit(ctx.json, &info, || {
                println!("Backup is valid.");
                println!("  Created:     {}", info.created_at);
                println!("  Vault id:    {}", info.vault_id);
                println!("  Schema:      v{}", info.schema_version);
                println!("  Projects:    {}", info.project_count);
                println!("  Credentials: {}", info.credential_count);
            });
        }
        BackupCmd::Restore { path, force, yes } => {
            if ctx.paths.vault_exists() {
                if !force {
                    bail!(
                        "a vault already exists at {}; pass --force to replace it \
                         (the current database is renamed aside, not deleted)",
                        ctx.paths.db_path().display()
                    );
                }
                if !ctx::confirm(
                    "Replace the current vault with the backup contents? The existing \
                     database will be renamed aside.",
                    yes,
                )? {
                    bail!("aborted");
                }
            }
            let backup_pw = ctx::backup_password(false)?;
            let info = backup::restore_backup(&path, &backup_pw, &ctx.paths, force)?;
            render::emit(ctx.json, &info, || {
                println!(
                    "Restored {} project(s) and {} credential(s) into {}.",
                    info.project_count,
                    info.credential_count,
                    ctx.paths.data_dir.display()
                );
                println!(
                    "Unlock with the master password that was set when this backup was created."
                );
            });
        }
    }
    Ok(())
}
