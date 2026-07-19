//! `api-tracker pricing` — inspect and maintain the versioned pricing
//! dataset used for local cost ESTIMATES (always labeled, always separate
//! from provider-reported cost).
//!
//! Records are effective-dated: estimation prices usage as of the usage
//! window's date, so importing a new price never silently reprices older
//! usage. Updates are reviewable by design: `pricing propose` writes a
//! template, the user verifies it against the provider's published pricing
//! page, edits it, and `pricing import` validates and applies it.

use crate::ctx::Ctx;
use crate::render;
use anyhow::{bail, Context, Result};
use api_tracker_core::pricing::{OverrideSpec, PricingRecord, Unit};
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum PricingCmd {
    /// List pricing records (currently effective by default).
    List(ListArgs),
    /// Show the record that prices a model at a date.
    Show(ShowArgs),
    /// Set a manual override (wins over imported and bundled records).
    SetOverride(SetOverrideArgs),
    /// Remove the manual override(s) for a model.
    RemoveOverride(KeyArgs),
    /// Import reviewed pricing records from a JSON file (validated).
    Import(ImportArgs),
    /// Export pricing records as reviewable JSON.
    Export(ExportArgs),
    /// Write a proposed-update template for a provider to review and edit.
    Propose(ProposeArgs),
}

#[derive(Args)]
pub struct ListArgs {
    /// Show the complete version history, not just effective records.
    #[arg(long)]
    pub all: bool,
    /// Only this provider.
    #[arg(long)]
    pub provider: Option<String>,
}

#[derive(Args)]
pub struct ShowArgs {
    pub provider: String,
    pub model: String,
    /// Price as of this date (YYYY-MM-DD; default today).
    #[arg(long)]
    pub as_of: Option<String>,
}

#[derive(Args)]
pub struct KeyArgs {
    pub provider: String,
    pub model: String,
}

#[derive(Args)]
pub struct SetOverrideArgs {
    pub provider: String,
    pub model: String,
    /// Input price per 1M tokens, in dollars (e.g. 2.50).
    #[arg(long)]
    pub input: Option<String>,
    /// Output price per 1M tokens, in dollars.
    #[arg(long)]
    pub output: Option<String>,
    /// Cached-input price per 1M tokens, in dollars.
    #[arg(long)]
    pub cached_input: Option<String>,
    /// Batch input price per 1M tokens, in dollars.
    #[arg(long)]
    pub batch_input: Option<String>,
    /// Batch output price per 1M tokens, in dollars.
    #[arg(long)]
    pub batch_output: Option<String>,
    /// Per-request price in dollars (request-unit pricing).
    #[arg(long)]
    pub per_request: Option<String>,
    /// Pricing unit: tokens (default) or requests.
    #[arg(long)]
    pub unit: Option<String>,
    /// The date this override takes effect (default: all usage dates).
    #[arg(long)]
    pub effective_from: Option<String>,
    /// Why this override exists (e.g. "negotiated rate").
    #[arg(long, default_value = "")]
    pub note: String,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Path to the reviewed pricing JSON file.
    pub file: String,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Only this provider.
    #[arg(long)]
    pub provider: Option<String>,
    /// Write to this file instead of stdout.
    #[arg(long)]
    pub out: Option<String>,
}

#[derive(Args)]
pub struct ProposeArgs {
    pub provider: String,
    /// Write to this file instead of stdout.
    #[arg(long)]
    pub out: Option<String>,
}

pub fn run(ctx: &Ctx, cmd: PricingCmd) -> Result<()> {
    match cmd {
        PricingCmd::List(a) => list(ctx, a),
        PricingCmd::Show(a) => show(ctx, a),
        PricingCmd::SetOverride(a) => set_override(ctx, a),
        PricingCmd::RemoveOverride(a) => remove_override(ctx, a),
        PricingCmd::Import(a) => import(ctx, a),
        PricingCmd::Export(a) => export(ctx, a),
        PricingCmd::Propose(a) => propose(ctx, a),
    }
}

fn dollars(m: Option<i64>) -> String {
    match m {
        Some(m) => format!("${:.2}", m as f64 / 1_000_000.0),
        None => "-".to_string(),
    }
}

fn record_rows(records: &[PricingRecord]) -> Vec<Vec<String>> {
    records
        .iter()
        .map(|r| {
            vec![
                render::sanitize(&r.provider),
                render::sanitize(&r.model),
                match r.unit {
                    Unit::Tokens => "tokens".into(),
                    Unit::Requests => "requests".into(),
                    Unit::Credits => "credits".into(),
                },
                dollars(r.input_price_per_m_micros),
                dollars(r.cached_input_price_per_m_micros),
                dollars(r.output_price_per_m_micros),
                dollars(r.per_request_micros),
                r.effective_from.clone(),
                r.last_verified.clone(),
                r.origin.as_str().to_string(),
                if r.stale { "STALE" } else { "" }.to_string(),
            ]
        })
        .collect()
}

const HEADERS: &[&str] = &[
    "PROVIDER",
    "MODEL",
    "UNIT",
    "IN/1M",
    "CACHED/1M",
    "OUT/1M",
    "PER-REQ",
    "EFFECTIVE",
    "VERIFIED",
    "ORIGIN",
    "",
];

fn list(ctx: &Ctx, a: ListArgs) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let mut records = if a.all {
        vault.pricing_catalog()?
    } else {
        vault.pricing_effective(&api_tracker_core::clock::now_rfc3339())?
    };
    if let Some(p) = &a.provider {
        let p = p.to_lowercase();
        records.retain(|r| r.provider == p);
    }
    render::emit(ctx.json, &records, || {
        if records.is_empty() {
            println!("no pricing records match");
            return;
        }
        render::table(HEADERS, &record_rows(&records));
        println!(
            "\nPrices are used for local ESTIMATES only and are kept separate from \
             provider-reported cost. {} of {} records are flagged stale (last verified \
             more than {} days ago).",
            records.iter().filter(|r| r.stale).count(),
            records.len(),
            api_tracker_core::pricing::STALE_AFTER_DAYS,
        );
        if !a.all {
            println!("Use --all for the full version history.");
        }
    });
    Ok(())
}

fn show(ctx: &Ctx, a: ShowArgs) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let as_of = a.as_of.unwrap_or_else(api_tracker_core::clock::now_rfc3339);
    let rec = vault.pricing_lookup(&a.provider, &a.model, &as_of)?;
    match rec {
        None => {
            render::emit(ctx.json, &serde_json::json!(null), || {
                println!(
                    "No pricing is known for {}/{} — estimates for this model are \
                     UNAVAILABLE (never invented). Add an override or import a reviewed \
                     record.",
                    render::sanitize(&a.provider),
                    render::sanitize(&a.model)
                );
            });
        }
        Some(rec) => {
            render::emit(ctx.json, &rec, || {
                render::table(HEADERS, &record_rows(std::slice::from_ref(&rec)));
                println!("source:   {}", render::sanitize(&rec.source));
                if !rec.note.is_empty() {
                    println!("note:     {}", render::sanitize(&rec.note));
                }
                if let Some(b) = rec.batch_input_price_per_m_micros {
                    println!(
                        "batch:    {} in / {} out per 1M",
                        dollars(Some(b)),
                        dollars(rec.batch_output_price_per_m_micros)
                    );
                }
                if rec.stale {
                    println!(
                        "\nWARNING: last verified {} — more than {} days ago. Verify the \
                         source and refresh.",
                        rec.last_verified,
                        api_tracker_core::pricing::STALE_AFTER_DAYS
                    );
                }
            });
        }
    }
    Ok(())
}

fn parse_dollars_opt(name: &str, v: &Option<String>) -> Result<Option<i64>> {
    match v {
        None => Ok(None),
        Some(s) => Ok(Some(
            api_tracker_core::pricing::dollars_to_micros(s).with_context(|| format!("--{name}"))?,
        )),
    }
}

fn set_override(ctx: &Ctx, a: SetOverrideArgs) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let unit = match a.unit.as_deref() {
        None => None,
        Some("tokens") => Some(Unit::Tokens),
        Some("requests") => Some(Unit::Requests),
        Some(other) => bail!("--unit must be tokens or requests (got '{other}')"),
    };
    let spec = OverrideSpec {
        unit,
        input_price_per_m_micros: parse_dollars_opt("input", &a.input)?,
        cached_input_price_per_m_micros: parse_dollars_opt("cached-input", &a.cached_input)?,
        output_price_per_m_micros: parse_dollars_opt("output", &a.output)?,
        batch_input_price_per_m_micros: parse_dollars_opt("batch-input", &a.batch_input)?,
        batch_output_price_per_m_micros: parse_dollars_opt("batch-output", &a.batch_output)?,
        per_request_micros: parse_dollars_opt("per-request", &a.per_request)?,
        effective_from: a.effective_from,
        note: a.note,
    };
    vault.set_pricing_override(&a.provider, &a.model, spec)?;
    println!(
        "Override stored for {}/{}. It wins over imported and bundled records; existing \
         stored estimates are NOT recomputed.",
        render::sanitize(&a.provider),
        render::sanitize(&a.model)
    );
    Ok(())
}

fn remove_override(ctx: &Ctx, a: KeyArgs) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let n = vault.remove_pricing_override(&a.provider, &a.model)?;
    if n == 0 {
        println!("no override existed for that model");
    } else {
        println!("removed {n} override record(s)");
    }
    Ok(())
}

fn import(ctx: &Ctx, a: ImportArgs) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let json =
        std::fs::read_to_string(&a.file).with_context(|| format!("could not read {}", a.file))?;
    let outcome = vault.pricing_import(&json)?;
    render::emit(ctx.json, &outcome, || {
        println!(
            "Imported {} new record(s); replaced {} record(s) with the same effective \
             date. Other history is preserved, and existing stored estimates are NOT \
             recomputed — future syncs price each usage window as of its own date.",
            outcome.added, outcome.replaced
        );
    });
    Ok(())
}

fn export(ctx: &Ctx, a: ExportArgs) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let json = vault.pricing_export(a.provider.as_deref())?;
    match &a.out {
        None => println!("{json}"),
        Some(path) => {
            std::fs::write(path, &json).with_context(|| format!("could not write {path}"))?;
            println!("wrote pricing export to {path}");
        }
    }
    Ok(())
}

fn propose(ctx: &Ctx, a: ProposeArgs) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let json = vault.pricing_propose(&a.provider)?;
    match &a.out {
        None => println!("{json}"),
        Some(path) => {
            std::fs::write(path, &json).with_context(|| format!("could not write {path}"))?;
            println!(
                "Wrote a proposed-update template to {path}.\nReview each price against \
                 the provider's published pricing page, edit the file, then run:\n  \
                 api-tracker pricing import {path}\nNothing changes until you import it.",
            );
        }
    }
    Ok(())
}
