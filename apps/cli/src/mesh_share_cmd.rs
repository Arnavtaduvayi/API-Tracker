//! `tethra mesh credential …`: opt-in credential sharing between your own
//! paired devices (Increment 11, ADR 0033).
//!
//! A share seals one credential's value to specific devices; each imports it
//! only when asked, after reauthentication. Nothing here prints a value: an
//! import prints the stored credential's masked form, and every list shows
//! names, devices and share ids only. Revoking a share never revokes the
//! credential at its provider, and a device keeps what it imported.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::mesh::membership::DeviceRow;
use api_tracker_core::mesh::share::{Recipients, ShareReceipt, ShareRow, SharesList};
use api_tracker_core::mesh::DeviceId;
use api_tracker_core::model::Environment;
use api_tracker_core::vault::{ImportOptions, UnlockedVault};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum CredentialCmd {
    /// Share one credential with your paired devices: its value is sealed to
    /// each device's key (reauthentication; it asks first). The credential's
    /// project must be shared (`tethra mesh project share`).
    Share {
        /// The credential (id, `project/name`, or a unique name).
        credential: String,
        /// A device to share with (id prefix or name; repeatable). Default:
        /// every current device, and a reseal offer for devices paired later.
        #[arg(long = "to", value_name = "DEVICE")]
        to: Vec<String>,
        /// Skip the confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Shares addressed to this device and shares it made, and any reseal
    /// offers. Never values.
    List,
    /// Import a share into a local project (reauthentication). The value is
    /// re-encrypted under that project's key.
    Import {
        /// The share id, or at least its first 8 characters.
        share: String,
        /// The local project to store it in.
        #[arg(long)]
        project: String,
        /// Replace the value of a same-named credential in that project (the
        /// old value is kept as a version).
        #[arg(long)]
        replace: bool,
        /// The environment of a newly created credential.
        #[arg(long, default_value = "development")]
        environment: String,
    },
    /// Revoke one share, or every share of a credential (it asks first).
    /// This does NOT revoke the credential at its provider, and a device
    /// that imported it keeps the value: rotate the credential to cut it off.
    Revoke {
        /// The share id (or at least its first 8 characters).
        #[arg(required_unless_present = "credential", conflicts_with = "credential")]
        share: Option<String>,
        /// Revoke every share this device made of this credential.
        #[arg(long)]
        credential: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Seal the current value to the devices a reseal offer names: devices
    /// paired since a share to all your devices, and devices holding an
    /// older value (reauthentication; it asks first).
    Reseal {
        credential: String,
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(ctx: &Ctx, cmd: CredentialCmd) -> Result<()> {
    match cmd {
        CredentialCmd::Share {
            credential,
            to,
            yes,
        } => share(ctx, &credential, &to, yes),
        CredentialCmd::List => list(ctx),
        CredentialCmd::Import {
            share,
            project,
            replace,
            environment,
        } => import(ctx, &share, &project, replace, &environment),
        CredentialCmd::Revoke {
            share,
            credential,
            yes,
        } => revoke(ctx, share.as_deref(), credential.as_deref(), yes),
        CredentialCmd::Reseal { credential, yes } => reseal(ctx, &credential, yes),
    }
}

fn short(hex: &str) -> &str {
    &hex[..8.min(hex.len())]
}

fn label(name: Option<&str>, id: &DeviceId) -> String {
    let hex = id.to_hex();
    match name {
        Some(n) => format!("{} ({})", render::sanitize(n), short(&hex)),
        None => short(&hex).to_owned(),
    }
}

fn row_label(d: &DeviceRow) -> String {
    label(d.name.as_deref(), &d.device_id)
}

/// A device by id prefix (≥ 8 hex characters) or by its name (unique,
/// case-insensitive).
fn resolve_device(devices: &[DeviceRow], ident: &str) -> Result<DeviceId> {
    let lower = ident.trim().to_ascii_lowercase();
    if lower.len() >= 8 && lower.bytes().all(|c| c.is_ascii_hexdigit()) {
        let hits: Vec<_> = devices
            .iter()
            .filter(|d| d.device_id.to_hex().starts_with(&lower))
            .collect();
        if hits.len() == 1 {
            return Ok(hits[0].device_id);
        }
    }
    let named: Vec<_> = devices
        .iter()
        .filter(|d| {
            d.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(ident.trim()))
        })
        .collect();
    match named.as_slice() {
        [one] => Ok(one.device_id),
        [] => bail!(
            "no device '{}' in this mesh (`tethra mesh devices`)",
            render::sanitize(ident)
        ),
        _ => bail!(
            "several devices are named '{}'; use the id",
            render::sanitize(ident)
        ),
    }
}

const REVOKE_NOTE: &str = "Revoking a share later does not revoke the credential at its provider, \
     and a device keeps whatever it imported: to cut a device off, rotate the credential \
     (`tethra rotation plan <credential>`).";

fn share(ctx: &Ctx, credential: &str, to: &[String], yes: bool) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let cred = vault.get_credential(credential)?;
    let devices = vault.mesh_devices()?;
    let recipients = if to.is_empty() {
        Recipients::AllCurrent
    } else {
        Recipients::Devices(
            to.iter()
                .map(|t| resolve_device(&devices, t))
                .collect::<Result<_>>()?,
        )
    };
    let named: Vec<String> = match &recipients {
        Recipients::AllCurrent => devices
            .iter()
            .filter(|d| d.active && !d.is_self)
            .map(row_label)
            .collect(),
        Recipients::Devices(ids) => ids
            .iter()
            .map(|id| {
                devices
                    .iter()
                    .find(|d| d.device_id == *id)
                    .map_or_else(|| short(&id.to_hex()).to_owned(), row_label)
            })
            .collect(),
    };
    if named.is_empty() {
        bail!(
            "there is no other active device to share with; pair one first (`tethra mesh invite`)"
        );
    }
    let question = format!(
        "Share the value of {}/{} ({}) with {}{}? Each can import it into its own vault. {}",
        render::sanitize(&cred.project_name),
        render::sanitize(&cred.name),
        render::sanitize(&cred.provider),
        named.join(", "),
        if matches!(recipients, Recipients::AllCurrent) {
            " (and offer it to devices you pair later)"
        } else {
            ""
        },
        REVOKE_NOTE
    );
    if !ctx::confirm(&question, yes)? {
        bail!("aborted");
    }
    eprintln!("Reauthentication required to share a credential.");
    let master = ctx::master_password()?;
    let receipt = vault.mesh_credential_share(&master, &cred.id, recipients)?;
    print_receipt(ctx, &receipt, "Shared");
    Ok(())
}

fn print_receipt(ctx: &Ctx, receipt: &ShareReceipt, verb: &str) {
    render::emit(ctx.json, receipt, || {
        println!(
            "{verb} {} with {} device(s), sealed to each device's key:",
            render::sanitize(&receipt.credential_name),
            receipt.recipients.len()
        );
        for r in &receipt.recipients {
            println!(
                "  {}  share {}",
                label(r.device_name.as_deref(), &r.device_id),
                short(&r.share_id.to_hex())
            );
        }
        println!(
            "Each device sees it after its next exchange and imports it with \
             `tethra mesh credential import <share> --project <local project>`."
        );
        println!("{REVOKE_NOTE}");
    });
}

fn state_of(r: &ShareRow, incoming: bool) -> String {
    if r.revoked {
        return "revoked".into();
    }
    if incoming {
        if !r.sharer_active && r.imported.is_none() {
            return "from a removed device (cannot be imported)".into();
        }
        return match &r.imported {
            Some(i) => format!(
                "imported as {}/{}",
                render::sanitize(&i.project_name),
                render::sanitize(&i.credential_name)
            ),
            None => "available".into(),
        };
    }
    if let Some(other) = &r.superseded_by {
        return format!(
            "replaced at the recipient by device {}'s share (reseal to send yours)",
            short(&other.to_hex())
        );
    }
    match r.current_value_version {
        Some(now) if now > r.value_version => format!("older value (now v{now})"),
        _ => "live".into(),
    }
}

fn list(ctx: &Ctx) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let out: SharesList = vault.mesh_shares_list()?;
    render::emit(ctx.json, &out, || {
        if out.incoming.is_empty() && out.outgoing.is_empty() {
            println!(
                "No credential shares. Share one with `tethra mesh credential share <credential>`."
            );
        }
        if !out.incoming.is_empty() {
            println!("Shared with this device:");
            let rows: Vec<Vec<String>> = out
                .incoming
                .iter()
                .map(|r| {
                    vec![
                        short(&r.share_id.to_hex()).to_owned(),
                        render::sanitize(&r.credential_name),
                        render::sanitize(&r.provider),
                        label(r.sharer_name.as_deref(), &r.sharer),
                        format!("v{}", r.value_version),
                        state_of(r, true),
                    ]
                })
                .collect();
            render::table(
                &[
                    "SHARE",
                    "CREDENTIAL",
                    "PROVIDER",
                    "FROM",
                    "VERSION",
                    "STATE",
                ],
                &rows,
            );
        }
        if !out.outgoing.is_empty() {
            println!("Shared by this device:");
            let rows: Vec<Vec<String>> = out
                .outgoing
                .iter()
                .map(|r| {
                    vec![
                        short(&r.share_id.to_hex()).to_owned(),
                        render::sanitize(&r.credential_name),
                        label(r.recipient_name.as_deref(), &r.recipient),
                        format!("v{}", r.value_version),
                        state_of(r, false),
                    ]
                })
                .collect();
            render::table(&["SHARE", "CREDENTIAL", "TO", "VERSION", "STATE"], &rows);
        }
        for o in &out.reseal_offers {
            println!(
                "Reseal offer: {}/{} for {} device(s) ({} paired since, {} with an older value); \
                 `tethra mesh credential reseal {}` (reauthentication).",
                render::sanitize(&o.project_name),
                render::sanitize(&o.credential_name),
                o.devices().len(),
                o.new_devices.len(),
                o.stale_devices.len(),
                o.credential_id
            );
        }
    });
    Ok(())
}

fn import(ctx: &Ctx, share: &str, project: &str, replace: bool, environment: &str) -> Result<()> {
    let environment: Environment = environment.parse()?;
    let (mut vault, _token) = ctx.unlocked()?;
    eprintln!("Reauthentication required to import a shared credential.");
    let master = ctx::master_password()?;
    let got = vault.mesh_credential_import(
        &master,
        share,
        project,
        ImportOptions {
            replace,
            environment,
        },
    )?;
    render::emit(ctx.json, &got, || {
        println!(
            "{} {}/{} ({}) from {}: {}",
            if got.replaced { "Replaced" } else { "Imported" },
            render::sanitize(&got.credential.project_name),
            render::sanitize(&got.credential.name),
            render::sanitize(&got.credential.provider),
            label(got.sharer_name.as_deref(), &got.sharer),
            // The mask keeps a few characters of a value another device chose.
            render::sanitize(&got.credential.masked_value)
        );
        if got.replaced {
            println!("The previous value is kept as a version (`tethra key versions`).");
        }
        for w in &got.reuse_warnings {
            println!("warning: {}", render::sanitize(&w.message));
        }
    });
    Ok(())
}

fn revoke(ctx: &Ctx, share: Option<&str>, credential: Option<&str>, yes: bool) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    // Name what a share id stands for (a share this device made; core
    // refuses any other).
    let named = share.and_then(|s| {
        let s = s.trim().to_ascii_lowercase();
        let out = vault.mesh_shares_peek().ok()?.outgoing;
        let hits: Vec<_> = out
            .iter()
            .filter(|r| !r.revoked && s.len() >= 8 && r.share_id.to_hex().starts_with(&s))
            .collect();
        match hits.as_slice() {
            [r] => Some(format!(
                "{} shared with {}",
                render::sanitize(&r.credential_name),
                label(r.recipient_name.as_deref(), &r.recipient)
            )),
            _ => None,
        }
    });
    let question = match (share, credential) {
        (Some(s), _) => format!(
            "Revoke share {}{}? {REVOKE_NOTE}",
            render::sanitize(s),
            named.map(|n| format!(" ({n})")).unwrap_or_default()
        ),
        (None, Some(c)) => format!(
            "Revoke every share of {} made from this device? {REVOKE_NOTE}",
            render::sanitize(c)
        ),
        (None, None) => bail!("give a share id or --credential"),
    };
    if !ctx::confirm(&question, yes)? {
        bail!("aborted");
    }
    let out = match (share, credential) {
        (Some(s), _) => vault.mesh_share_revoke(s)?,
        (None, Some(c)) => vault.mesh_credential_revoke(c)?,
        (None, None) => unreachable!("checked above"),
    };
    render::emit(ctx.json, &out, || {
        println!("Revoked {} share(s):", out.len());
        for r in &out {
            println!(
                "  {} to {}",
                render::sanitize(&r.credential_name),
                label(r.recipient_name.as_deref(), &r.recipient)
            );
        }
        println!("{REVOKE_NOTE}");
    });
    Ok(())
}

fn reseal(ctx: &Ctx, credential: &str, yes: bool) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let cred = vault.get_credential(credential)?;
    let offers = vault.mesh_shares_list()?.reseal_offers;
    let Some(offer) = offers.iter().find(|o| o.credential_id == cred.id) else {
        bail!("there is nothing to reseal for this credential: every device it was shared with has its current value");
    };
    let devices = vault.mesh_devices()?;
    let names: Vec<String> = offer
        .devices()
        .iter()
        .map(|id| {
            devices
                .iter()
                .find(|d| d.device_id == *id)
                .map_or_else(|| short(&id.to_hex()).to_owned(), row_label)
        })
        .collect();
    let question = format!(
        "Seal the current value of {}/{} to {}?",
        render::sanitize(&cred.project_name),
        render::sanitize(&cred.name),
        names.join(", ")
    );
    if !ctx::confirm(&question, yes)? {
        bail!("aborted");
    }
    eprintln!("Reauthentication required to reseal a credential.");
    let master = ctx::master_password()?;
    let receipt = vault.mesh_credential_reseal(&master, &cred.id)?;
    print_receipt(ctx, &receipt, "Resealed");
    Ok(())
}

/// A one-line summary of the shares, for `tethra mesh status` (no writes).
pub fn status_summary(vault: &UnlockedVault) -> Result<SharesSummary> {
    let l = vault.mesh_shares_peek()?;
    Ok(SharesSummary {
        incoming_available: l
            .incoming
            .iter()
            .filter(|r| !r.revoked && r.imported.is_none())
            .count(),
        incoming_imported: l.incoming.iter().filter(|r| r.imported.is_some()).count(),
        outgoing_live: l.outgoing.iter().filter(|r| !r.revoked).count(),
        reseal_offers: l.reseal_offers.len(),
    })
}

/// `mesh status`'s `shares` object.
#[derive(serde::Serialize)]
pub struct SharesSummary {
    pub incoming_available: usize,
    pub incoming_imported: usize,
    pub outgoing_live: usize,
    pub reseal_offers: usize,
}
