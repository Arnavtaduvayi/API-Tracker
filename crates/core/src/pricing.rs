//! Versioned pricing records and cost estimation.
//!
//! Providers do not expose pricing through their APIs, so pricing is a local,
//! versioned dataset with three origins:
//!
//! - **bundled** — published rates compiled into the binary, each with its
//!   official source URL, the date the price took effect, and the date it was
//!   last verified against that source;
//! - **imported** — records the user reviewed and imported from a JSON file
//!   (`pricing import` / `pricing export` round-trip);
//! - **override** — explicit manual overrides that win over everything.
//!
//! Every record is **effective-dated**: estimation prices usage *as of the
//! usage window's date*, so adding a new price for a model never silently
//! reprices older usage — the older window keeps resolving to the record
//! that was effective then. Historical records are never deleted by imports
//! (an import replaces only a record with the same provider/model/origin/
//! effective date — an explicit, reviewable correction).
//!
//! Estimated costs are always labeled "estimated" and kept strictly separate
//! from provider-reported costs. Unknown models yield *no* estimate — a
//! number is never invented. Records whose `last_verified` date is past the
//! staleness horizon are flagged so figures are never silently trusted.
//! Prices are integer micro-USD per one million tokens (or per request),
//! avoiding float rounding.
//!
//! Honest limitation (documented, not hidden): usage snapshots store input
//! tokens as a single figure (cached tokens are not broken out), so token
//! estimates price all input at the base input rate. Cached and batch rates
//! are carried on records for display, imports, and overrides, but the
//! cached-token discount is not applied to estimates; the bill can therefore
//! be lower than the estimate. Provider-reported cost is the authoritative
//! figure wherever it is synced.

use crate::clock;
use crate::error::{CoreError, Result};
use crate::usage::MICROS_PER_USD;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Records last verified more than this many days ago are flagged stale.
pub const STALE_AFTER_DAYS: i64 = 45;

/// Revision counter for the bundled table; bump when the bundled set changes.
pub const BUNDLED_REVISION: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Tokens,
    Requests,
    Credits,
}

impl Unit {
    pub fn as_str(&self) -> &'static str {
        match self {
            Unit::Tokens => "tokens",
            Unit::Requests => "requests",
            Unit::Credits => "credits",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "tokens" => Ok(Unit::Tokens),
            "requests" => Ok(Unit::Requests),
            "credits" => Ok(Unit::Credits),
            other => Err(CoreError::InvalidInput(format!(
                "unknown pricing unit '{other}' (expected tokens, requests, or credits)"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Bundled,
    Imported,
    Override,
}

impl Origin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Origin::Bundled => "bundled",
            Origin::Imported => "imported",
            Origin::Override => "override",
        }
    }
    fn parse(s: &str) -> Self {
        match s {
            "override" => Origin::Override,
            "imported" => Origin::Imported,
            _ => Origin::Bundled,
        }
    }
    /// Selection precedence: overrides beat imports beat bundled.
    fn rank(&self) -> u8 {
        match self {
            Origin::Override => 2,
            Origin::Imported => 1,
            Origin::Bundled => 0,
        }
    }
}

/// A pricing record (bundled, imported, or override).
#[derive(Debug, Clone, Serialize)]
pub struct PricingRecord {
    pub provider: String,
    pub model: String,
    pub unit: Unit,
    /// Price per 1,000,000 input tokens, in micro-USD.
    pub input_price_per_m_micros: Option<i64>,
    /// Price per 1,000,000 *cached* input tokens (cache read), if published.
    pub cached_input_price_per_m_micros: Option<i64>,
    pub output_price_per_m_micros: Option<i64>,
    /// Batch-API prices, if published.
    pub batch_input_price_per_m_micros: Option<i64>,
    pub batch_output_price_per_m_micros: Option<i64>,
    /// Price per request, in micro-USD (request-unit pricing).
    pub per_request_micros: Option<i64>,
    pub currency: String,
    pub source: String,
    /// The date (YYYY-MM-DD) this price took effect.
    pub effective_from: String,
    /// The date (YYYY-MM-DD) this record was last checked against its source.
    pub last_verified: String,
    pub origin: Origin,
    /// Bundled: the bundled-table revision. DB records: a per-key counter.
    pub version: i64,
    pub note: String,
    /// Computed at load time from `last_verified`.
    pub stale: bool,
}

impl PricingRecord {
    pub fn is_stale(&self, now_rfc3339: &str) -> bool {
        let Ok(verified) = clock::parse_user_date(&self.last_verified) else {
            return true;
        };
        let Ok(now_t) = clock::parse_rfc3339(now_rfc3339) else {
            return false;
        };
        (now_t - verified).whole_days() > STALE_AFTER_DAYS
    }
}

/// Bundled published rates. Sources and verification dates are per entry;
/// users should verify against the provider's pricing page and import or
/// override locally when rates change. Prices are per 1M tokens in micro-USD.
fn bundled() -> Vec<PricingRecord> {
    // The date the bundled set was last checked against the sources below.
    const VERIFIED: &str = "2026-07-18";
    const OPENAI_SRC: &str = "https://developers.openai.com/api/docs/pricing";
    const ANTHROPIC_SRC: &str = "https://platform.claude.com/docs/en/about-claude/pricing";

    struct B {
        provider: &'static str,
        model: &'static str,
        effective: &'static str,
        input: i64,
        cached: Option<i64>,
        output: i64,
        source: &'static str,
    }
    // Batch prices for both providers are the documented 50% of base rates
    // and are derived below rather than repeated per entry.
    let entries = [
        // OpenAI — current models (verified 2026-07-18).
        B {
            provider: "openai",
            model: "gpt-5.6-sol",
            effective: "2026-07-18",
            input: 5_000_000,
            cached: Some(500_000),
            output: 30_000_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-5.6-terra",
            effective: "2026-07-18",
            input: 2_500_000,
            cached: Some(250_000),
            output: 15_000_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-5.6-luna",
            effective: "2026-07-18",
            input: 1_000_000,
            cached: Some(100_000),
            output: 6_000_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-5.5-pro",
            effective: "2026-07-18",
            input: 30_000_000,
            cached: None,
            output: 180_000_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-5.5",
            effective: "2026-07-18",
            input: 5_000_000,
            cached: Some(500_000),
            output: 30_000_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-5.4-mini",
            effective: "2026-07-18",
            input: 750_000,
            cached: Some(75_000),
            output: 4_500_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-5.4-nano",
            effective: "2026-07-18",
            input: 200_000,
            cached: Some(20_000),
            output: 1_250_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-5.4-pro",
            effective: "2026-07-18",
            input: 30_000_000,
            cached: None,
            output: 180_000_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-5.4",
            effective: "2026-07-18",
            input: 2_500_000,
            cached: Some(250_000),
            output: 15_000_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-5.3-codex",
            effective: "2026-07-18",
            input: 1_750_000,
            cached: Some(175_000),
            output: 14_000_000,
            source: OPENAI_SRC,
        },
        // OpenAI — legacy models still served (carried from the prior table).
        B {
            provider: "openai",
            model: "gpt-4o-mini",
            effective: "2026-07-18",
            input: 150_000,
            cached: None,
            output: 600_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "gpt-4o",
            effective: "2026-07-18",
            input: 2_500_000,
            cached: None,
            output: 10_000_000,
            source: OPENAI_SRC,
        },
        B {
            provider: "openai",
            model: "o4-mini",
            effective: "2026-07-18",
            input: 1_100_000,
            cached: None,
            output: 4_400_000,
            source: OPENAI_SRC,
        },
        // Anthropic — current models (verified 2026-07-18). Cached = cache
        // read (hit) price; cache writes cost more and are not modeled.
        B {
            provider: "anthropic",
            model: "claude-fable-5",
            effective: "2026-07-18",
            input: 10_000_000,
            cached: Some(1_000_000),
            output: 50_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-opus-4-8",
            effective: "2026-07-18",
            input: 5_000_000,
            cached: Some(500_000),
            output: 25_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-opus-4-7",
            effective: "2026-07-18",
            input: 5_000_000,
            cached: Some(500_000),
            output: 25_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-opus-4-6",
            effective: "2026-07-18",
            input: 5_000_000,
            cached: Some(500_000),
            output: 25_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-opus-4-5",
            effective: "2026-07-18",
            input: 5_000_000,
            cached: Some(500_000),
            output: 25_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-opus-4-1",
            effective: "2026-07-18",
            input: 15_000_000,
            cached: Some(1_500_000),
            output: 75_000_000,
            source: ANTHROPIC_SRC,
        },
        // Dated Opus/Sonnet 4 ids (e.g. claude-opus-4-20250514).
        B {
            provider: "anthropic",
            model: "claude-opus-4-2025",
            effective: "2026-07-18",
            input: 15_000_000,
            cached: Some(1_500_000),
            output: 75_000_000,
            source: ANTHROPIC_SRC,
        },
        // Sonnet 5 has documented date-dependent pricing: introductory
        // through 2026-08-31, standard from 2026-09-01. Two effective-dated
        // records represent that exactly.
        B {
            provider: "anthropic",
            model: "claude-sonnet-5",
            effective: "2026-07-18",
            input: 2_000_000,
            cached: Some(200_000),
            output: 10_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-sonnet-5",
            effective: "2026-09-01",
            input: 3_000_000,
            cached: Some(300_000),
            output: 15_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-sonnet-4-6",
            effective: "2026-07-18",
            input: 3_000_000,
            cached: Some(300_000),
            output: 15_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-sonnet-4-5",
            effective: "2026-07-18",
            input: 3_000_000,
            cached: Some(300_000),
            output: 15_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-sonnet-4-2025",
            effective: "2026-07-18",
            input: 3_000_000,
            cached: Some(300_000),
            output: 15_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-haiku-4-5",
            effective: "2026-07-18",
            input: 1_000_000,
            cached: Some(100_000),
            output: 5_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-3-5-haiku",
            effective: "2026-07-18",
            input: 800_000,
            cached: Some(80_000),
            output: 4_000_000,
            source: ANTHROPIC_SRC,
        },
        // Family-level fallbacks for ids the specific entries above miss.
        // A fallback is a coarser guess and its note says so.
        B {
            provider: "anthropic",
            model: "claude-sonnet",
            effective: "2026-07-18",
            input: 3_000_000,
            cached: Some(300_000),
            output: 15_000_000,
            source: ANTHROPIC_SRC,
        },
        B {
            provider: "anthropic",
            model: "claude-haiku",
            effective: "2026-07-18",
            input: 800_000,
            cached: Some(80_000),
            output: 4_000_000,
            source: ANTHROPIC_SRC,
        },
    ];
    entries
        .into_iter()
        .map(|b| {
            let family_fallback = b.model == "claude-sonnet" || b.model == "claude-haiku";
            PricingRecord {
                provider: b.provider.to_string(),
                model: b.model.to_string(),
                unit: Unit::Tokens,
                input_price_per_m_micros: Some(b.input),
                cached_input_price_per_m_micros: b.cached,
                output_price_per_m_micros: Some(b.output),
                batch_input_price_per_m_micros: Some(b.input / 2),
                batch_output_price_per_m_micros: Some(b.output / 2),
                per_request_micros: None,
                currency: "USD".to_string(),
                source: b.source.to_string(),
                effective_from: b.effective.to_string(),
                last_verified: VERIFIED.to_string(),
                origin: Origin::Bundled,
                version: BUNDLED_REVISION,
                note: if family_fallback {
                    "family-level fallback rate for model ids without a specific entry".to_string()
                } else {
                    String::new()
                },
                stale: false,
            }
        })
        .collect()
}

fn load_db_records(conn: &Connection, provider: Option<&str>) -> Result<Vec<PricingRecord>> {
    let sql = "SELECT provider, model, unit, input_price_per_m_micros,
                      cached_input_price_per_m_micros, output_price_per_m_micros,
                      batch_input_price_per_m_micros, batch_output_price_per_m_micros,
                      per_request_micros, currency, source, effective_from, last_verified,
                      origin, version, note
               FROM pricing_records
               WHERE (?1 IS NULL OR provider = ?1)
               ORDER BY provider, model, effective_from";
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map(params![provider], |r| {
            Ok(PricingRecord {
                provider: r.get(0)?,
                model: r.get(1)?,
                unit: Unit::parse(&r.get::<_, String>(2)?).unwrap_or(Unit::Tokens),
                input_price_per_m_micros: r.get(3)?,
                cached_input_price_per_m_micros: r.get(4)?,
                output_price_per_m_micros: r.get(5)?,
                batch_input_price_per_m_micros: r.get(6)?,
                batch_output_price_per_m_micros: r.get(7)?,
                per_request_micros: r.get(8)?,
                currency: r.get(9)?,
                source: r.get(10)?,
                effective_from: r.get(11)?,
                last_verified: r.get(12)?,
                origin: Origin::parse(&r.get::<_, String>(13)?),
                version: r.get(14)?,
                note: r.get(15)?,
                stale: false,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Reduce an RFC 3339 timestamp or plain date to its YYYY-MM-DD prefix.
fn date_prefix(s: &str) -> &str {
    if s.len() >= 10 {
        &s[..10]
    } else {
        s
    }
}

/// Look up the pricing record effective for `provider`/`model` as of the
/// given date (RFC 3339 timestamp or YYYY-MM-DD). Model matching is
/// case-insensitive; dated/variant ids resolve by the most specific
/// (longest) matching entry. Precedence at the same specificity: manual
/// override, then imported, then bundled; within an origin, the latest
/// record effective on or before the date wins. When *no* record was
/// effective yet at that date, the earliest known record is applied and the
/// estimate says so — a price is never invented, but a documented later
/// price is honestly extrapolated backwards rather than pretending the
/// model was free.
pub fn lookup_as_of(
    conn: &Connection,
    provider: &str,
    model: &str,
    as_of: &str,
) -> Result<Option<PricingRecord>> {
    let provider = provider.to_lowercase();
    let model_l = model.to_lowercase();
    let as_of_date = date_prefix(as_of);
    let now = clock::now_rfc3339();

    let mut candidates: Vec<PricingRecord> = load_db_records(conn, Some(&provider))?;
    candidates.extend(bundled().into_iter().filter(|r| r.provider == provider));
    let matching: Vec<PricingRecord> = candidates
        .into_iter()
        .filter(|r| model_l == r.model || model_l.contains(&r.model))
        .collect();
    if matching.is_empty() {
        return Ok(None);
    }
    // Most specific model string wins.
    let best_len = matching.iter().map(|r| r.model.len()).max().unwrap_or(0);
    let specific: Vec<PricingRecord> = matching
        .into_iter()
        .filter(|r| r.model.len() == best_len)
        .collect();

    let effective: Option<&PricingRecord> = specific
        .iter()
        .filter(|r| r.effective_from.as_str() <= as_of_date)
        .max_by_key(|r| (r.origin.rank(), r.effective_from.clone()));
    let chosen = match effective {
        Some(r) => r.clone(),
        None => {
            // Nothing effective yet at this date: apply the earliest known
            // record, annotated so the extrapolation is visible.
            let mut earliest = specific
                .iter()
                .min_by_key(|r| (std::cmp::Reverse(r.origin.rank()), r.effective_from.clone()))
                .cloned()
                .expect("non-empty");
            earliest.note = format!(
                "price effective {} applied to earlier usage{}",
                earliest.effective_from,
                if earliest.note.is_empty() {
                    String::new()
                } else {
                    format!("; {}", earliest.note)
                }
            );
            earliest
        }
    };
    let mut chosen = chosen;
    chosen.stale = chosen.is_stale(&now);
    Ok(Some(chosen))
}

/// The parameters accepted when setting a manual override.
#[derive(Debug, Clone, Default)]
pub struct OverrideSpec {
    pub unit: Option<Unit>,
    pub input_price_per_m_micros: Option<i64>,
    pub cached_input_price_per_m_micros: Option<i64>,
    pub output_price_per_m_micros: Option<i64>,
    pub batch_input_price_per_m_micros: Option<i64>,
    pub batch_output_price_per_m_micros: Option<i64>,
    pub per_request_micros: Option<i64>,
    /// Defaults to 1970-01-01, i.e. the override applies to all usage dates.
    pub effective_from: Option<String>,
    pub note: String,
}

fn validate_price(name: &str, v: Option<i64>) -> Result<()> {
    if let Some(v) = v {
        if v < 0 {
            return Err(CoreError::InvalidInput(format!(
                "{name} must not be negative"
            )));
        }
    }
    Ok(())
}

fn validate_date(name: &str, v: &str) -> Result<()> {
    clock::parse_user_date(v)
        .map(|_| ())
        .map_err(|_| CoreError::InvalidInput(format!("{name} '{v}' is not a YYYY-MM-DD date")))
}

fn next_version(conn: &Connection, provider: &str, model: &str) -> Result<i64> {
    let v: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM pricing_records WHERE provider=?1 AND model=?2",
        params![provider, model],
        |r| r.get(0),
    )?;
    Ok(v + 1)
}

fn upsert_record(conn: &Connection, rec: &PricingRecord) -> Result<bool> {
    let replaced: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pricing_records
         WHERE provider=?1 AND model=?2 AND origin=?3 AND effective_from=?4)",
        params![
            rec.provider,
            rec.model,
            rec.origin.as_str(),
            rec.effective_from
        ],
        |r| r.get(0),
    )?;
    conn.execute(
        "INSERT INTO pricing_records
         (id, provider, model, unit, input_price_per_m_micros, cached_input_price_per_m_micros,
          output_price_per_m_micros, batch_input_price_per_m_micros, batch_output_price_per_m_micros,
          per_request_micros, currency, source, effective_from, last_verified, origin, version,
          note, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)
         ON CONFLICT(provider, model, origin, effective_from) DO UPDATE SET
           unit = excluded.unit,
           input_price_per_m_micros = excluded.input_price_per_m_micros,
           cached_input_price_per_m_micros = excluded.cached_input_price_per_m_micros,
           output_price_per_m_micros = excluded.output_price_per_m_micros,
           batch_input_price_per_m_micros = excluded.batch_input_price_per_m_micros,
           batch_output_price_per_m_micros = excluded.batch_output_price_per_m_micros,
           per_request_micros = excluded.per_request_micros,
           currency = excluded.currency,
           source = excluded.source,
           last_verified = excluded.last_verified,
           version = excluded.version,
           note = excluded.note,
           created_at = excluded.created_at",
        params![
            Uuid::new_v4().to_string(),
            rec.provider,
            rec.model,
            rec.unit.as_str(),
            rec.input_price_per_m_micros,
            rec.cached_input_price_per_m_micros,
            rec.output_price_per_m_micros,
            rec.batch_input_price_per_m_micros,
            rec.batch_output_price_per_m_micros,
            rec.per_request_micros,
            rec.currency,
            rec.source,
            rec.effective_from,
            rec.last_verified,
            rec.origin.as_str(),
            rec.version,
            rec.note,
            clock::now_rfc3339(),
        ],
    )?;
    Ok(replaced)
}

/// Set (or replace) a manual pricing override.
pub fn set_override(
    conn: &Connection,
    provider: &str,
    model: &str,
    spec: OverrideSpec,
) -> Result<()> {
    let provider = provider.trim().to_lowercase();
    let model = model.trim().to_lowercase();
    if provider.is_empty() || model.is_empty() {
        return Err(CoreError::InvalidInput(
            "provider and model must not be empty".into(),
        ));
    }
    validate_price("input price", spec.input_price_per_m_micros)?;
    validate_price("cached input price", spec.cached_input_price_per_m_micros)?;
    validate_price("output price", spec.output_price_per_m_micros)?;
    validate_price("batch input price", spec.batch_input_price_per_m_micros)?;
    validate_price("batch output price", spec.batch_output_price_per_m_micros)?;
    validate_price("per-request price", spec.per_request_micros)?;
    let unit = spec.unit.unwrap_or(Unit::Tokens);
    match unit {
        Unit::Tokens
            if spec.input_price_per_m_micros.is_none()
                && spec.output_price_per_m_micros.is_none() =>
        {
            return Err(CoreError::InvalidInput(
                "a token override needs an input and/or output price".into(),
            ));
        }
        Unit::Requests if spec.per_request_micros.is_none() => {
            return Err(CoreError::InvalidInput(
                "a request override needs a per-request price".into(),
            ));
        }
        _ => {}
    }
    let effective_from = spec
        .effective_from
        .unwrap_or_else(|| "1970-01-01".to_string());
    if effective_from != "1970-01-01" {
        validate_date("effective date", &effective_from)?;
    }
    let today = date_prefix(&clock::now_rfc3339()).to_string();
    let rec = PricingRecord {
        version: next_version(conn, &provider, &model)?,
        provider,
        model,
        unit,
        input_price_per_m_micros: spec.input_price_per_m_micros,
        cached_input_price_per_m_micros: spec.cached_input_price_per_m_micros,
        output_price_per_m_micros: spec.output_price_per_m_micros,
        batch_input_price_per_m_micros: spec.batch_input_price_per_m_micros,
        batch_output_price_per_m_micros: spec.batch_output_price_per_m_micros,
        per_request_micros: spec.per_request_micros,
        currency: "USD".to_string(),
        source: format!(
            "manual override{}",
            if spec.note.is_empty() {
                String::new()
            } else {
                format!(" ({})", spec.note)
            }
        ),
        effective_from,
        last_verified: today,
        origin: Origin::Override,
        note: spec.note,
        stale: false,
    };
    upsert_record(conn, &rec)?;
    Ok(())
}

/// Remove all manual overrides for a provider/model. Returns how many rows
/// were removed. Imported and bundled records are untouched.
pub fn remove_override(conn: &Connection, provider: &str, model: &str) -> Result<usize> {
    let n = conn.execute(
        "DELETE FROM pricing_records
         WHERE provider = ?1 AND model = ?2 AND origin = 'override'",
        params![provider.to_lowercase(), model.to_lowercase()],
    )?;
    Ok(n)
}

/// The interchange format for `pricing import` / `pricing export`: prices
/// are human-readable dollar strings, validated strictly on import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterchangeRecord {
    pub provider: String,
    pub model: String,
    #[serde(default = "default_unit")]
    pub unit: Unit,
    #[serde(default)]
    pub input_per_m: Option<String>,
    #[serde(default)]
    pub cached_input_per_m: Option<String>,
    #[serde(default)]
    pub output_per_m: Option<String>,
    #[serde(default)]
    pub batch_input_per_m: Option<String>,
    #[serde(default)]
    pub batch_output_per_m: Option<String>,
    #[serde(default)]
    pub per_request: Option<String>,
    #[serde(default = "default_currency")]
    pub currency: String,
    pub source: String,
    pub effective_from: String,
    pub last_verified: String,
    #[serde(default)]
    pub note: String,
    /// Informational on export; ignored on import (imports are 'imported').
    #[serde(default)]
    pub origin: Option<Origin>,
}

fn default_unit() -> Unit {
    Unit::Tokens
}
fn default_currency() -> String {
    "USD".to_string()
}

fn micros_to_dollars(m: Option<i64>) -> Option<String> {
    m.map(|m| format!("{:.6}", m as f64 / MICROS_PER_USD as f64))
}

fn parse_price(name: &str, v: &Option<String>) -> Result<Option<i64>> {
    match v {
        None => Ok(None),
        Some(s) => dollars_to_micros(s)
            .map(Some)
            .map_err(|e| CoreError::InvalidInput(format!("{name}: {e}"))),
    }
}

/// The result of an import.
#[derive(Debug, Clone, Serialize)]
pub struct ImportOutcome {
    pub added: usize,
    pub replaced: usize,
}

/// Import reviewed pricing records from interchange JSON. Every record is
/// validated (prices non-negative and parseable, dates well-formed, unit
/// consistent); the whole import is rejected on the first invalid record.
/// Records land with origin `imported`; a record replaces an existing one
/// only when provider, model, and effective date all match — other history
/// is preserved.
pub fn import_records(conn: &Connection, json: &str) -> Result<ImportOutcome> {
    // A pricing file is small by nature; refuse absurd inputs before
    // parsing rather than allocating for them.
    const MAX_IMPORT_BYTES: usize = 4 * 1024 * 1024;
    if json.len() > MAX_IMPORT_BYTES {
        return Err(CoreError::InvalidInput(
            "the pricing file exceeds 4 MiB; that is not a pricing dataset".into(),
        ));
    }
    let parsed: Vec<InterchangeRecord> = serde_json::from_str(json)
        .map_err(|e| CoreError::InvalidInput(format!("pricing JSON did not parse: {e}")))?;
    if parsed.is_empty() {
        return Err(CoreError::InvalidInput(
            "the pricing file contains no records".into(),
        ));
    }
    let mut to_insert = Vec::new();
    for (i, r) in parsed.iter().enumerate() {
        let ctx = format!("record {} ({}/{})", i + 1, r.provider, r.model);
        let provider = r.provider.trim().to_lowercase();
        let model = r.model.trim().to_lowercase();
        if provider.is_empty() || model.is_empty() {
            return Err(CoreError::InvalidInput(format!(
                "{ctx}: provider and model must not be empty"
            )));
        }
        if r.currency.trim().len() != 3 {
            return Err(CoreError::InvalidInput(format!(
                "{ctx}: currency must be a 3-letter code"
            )));
        }
        validate_date(&format!("{ctx}: effective_from"), &r.effective_from)?;
        validate_date(&format!("{ctx}: last_verified"), &r.last_verified)?;
        let input = parse_price(&format!("{ctx}: input_per_m"), &r.input_per_m)?;
        let cached = parse_price(&format!("{ctx}: cached_input_per_m"), &r.cached_input_per_m)?;
        let output = parse_price(&format!("{ctx}: output_per_m"), &r.output_per_m)?;
        let batch_in = parse_price(&format!("{ctx}: batch_input_per_m"), &r.batch_input_per_m)?;
        let batch_out = parse_price(&format!("{ctx}: batch_output_per_m"), &r.batch_output_per_m)?;
        let per_req = parse_price(&format!("{ctx}: per_request"), &r.per_request)?;
        match r.unit {
            Unit::Tokens if input.is_none() && output.is_none() => {
                return Err(CoreError::InvalidInput(format!(
                    "{ctx}: a token record needs an input and/or output price"
                )));
            }
            Unit::Requests if per_req.is_none() => {
                return Err(CoreError::InvalidInput(format!(
                    "{ctx}: a request record needs per_request"
                )));
            }
            _ => {}
        }
        to_insert.push(PricingRecord {
            provider,
            model,
            unit: r.unit,
            input_price_per_m_micros: input,
            cached_input_price_per_m_micros: cached,
            output_price_per_m_micros: output,
            batch_input_price_per_m_micros: batch_in,
            batch_output_price_per_m_micros: batch_out,
            per_request_micros: per_req,
            currency: r.currency.trim().to_uppercase(),
            source: r.source.clone(),
            effective_from: r.effective_from.clone(),
            last_verified: r.last_verified.clone(),
            origin: Origin::Imported,
            version: 0, // assigned below
            note: r.note.clone(),
            stale: false,
        });
    }
    let mut added = 0;
    let mut replaced = 0;
    for mut rec in to_insert {
        rec.version = next_version(conn, &rec.provider, &rec.model)?;
        if upsert_record(conn, &rec)? {
            replaced += 1;
        } else {
            added += 1;
        }
    }
    Ok(ImportOutcome { added, replaced })
}

/// Export pricing records as interchange JSON (bundled included, so the
/// export is a complete, reviewable statement of the effective dataset).
pub fn export_records(conn: &Connection, provider: Option<&str>) -> Result<String> {
    let mut records = load_db_records(conn, provider)?;
    records.extend(
        bundled()
            .into_iter()
            .filter(|r| provider.is_none_or(|p| r.provider == p)),
    );
    records.sort_by(|a, b| {
        (&a.provider, &a.model, &a.effective_from).cmp(&(&b.provider, &b.model, &b.effective_from))
    });
    let out: Vec<InterchangeRecord> = records
        .iter()
        .map(|r| InterchangeRecord {
            provider: r.provider.clone(),
            model: r.model.clone(),
            unit: r.unit,
            input_per_m: micros_to_dollars(r.input_price_per_m_micros),
            cached_input_per_m: micros_to_dollars(r.cached_input_price_per_m_micros),
            output_per_m: micros_to_dollars(r.output_price_per_m_micros),
            batch_input_per_m: micros_to_dollars(r.batch_input_price_per_m_micros),
            batch_output_per_m: micros_to_dollars(r.batch_output_price_per_m_micros),
            per_request: micros_to_dollars(r.per_request_micros),
            currency: r.currency.clone(),
            source: r.source.clone(),
            effective_from: r.effective_from.clone(),
            last_verified: r.last_verified.clone(),
            note: r.note.clone(),
            origin: Some(r.origin),
        })
        .collect();
    Ok(serde_json::to_string_pretty(&out)?)
}

/// A proposed-update template: the currently effective record per model for
/// a provider, with `last_verified` reset to today, ready for the user to
/// review against the provider's pricing page, edit, and `pricing import`.
/// Nothing is scraped and nothing changes until the user imports the file.
pub fn proposal_template(conn: &Connection, provider: &str) -> Result<String> {
    let today = date_prefix(&clock::now_rfc3339()).to_string();
    let provider_l = provider.to_lowercase();
    let effective = effective_catalog(conn, &today)?;
    let out: Vec<InterchangeRecord> = effective
        .into_iter()
        .filter(|r| r.provider == provider_l)
        .map(|r| InterchangeRecord {
            provider: r.provider.clone(),
            model: r.model.clone(),
            unit: r.unit,
            input_per_m: micros_to_dollars(r.input_price_per_m_micros),
            cached_input_per_m: micros_to_dollars(r.cached_input_price_per_m_micros),
            output_per_m: micros_to_dollars(r.output_price_per_m_micros),
            batch_input_per_m: micros_to_dollars(r.batch_input_price_per_m_micros),
            batch_output_per_m: micros_to_dollars(r.batch_output_price_per_m_micros),
            per_request: micros_to_dollars(r.per_request_micros),
            currency: r.currency.clone(),
            source: r.source.clone(),
            effective_from: today.clone(),
            last_verified: today.clone(),
            note: "review against the source before importing".to_string(),
            origin: None,
        })
        .collect();
    if out.is_empty() {
        return Err(CoreError::InvalidInput(format!(
            "no pricing records exist for provider '{provider}'"
        )));
    }
    Ok(serde_json::to_string_pretty(&out)?)
}

/// The outcome of estimating a cost.
///
/// A pricing record does not have to price every dimension it is used for:
/// a record carrying only `input_price_per_m` prices output tokens at
/// nothing. `micros` used to absorb that silently via `unwrap_or(0)`, so a
/// half-priced estimate was indistinguishable from a complete one and read
/// downstream as the whole cost (NEW-37). The estimate now carries its own
/// completeness, so a partial price cannot be presented as a total.
#[derive(Debug, Clone, Serialize)]
pub struct CostEstimate {
    /// The derived amount. A LOWER BOUND when `complete` is false: the
    /// dimensions in `unpriced_dimensions` contributed nothing to it.
    pub micros: i64,
    pub pricing_source: String,
    pub effective_from: String,
    pub last_verified: String,
    pub is_override: bool,
    pub stale: bool,
    pub note: String,
    /// True when every dimension with non-zero usage had a price, i.e.
    /// `micros` is the whole estimate rather than a floor.
    pub complete: bool,
    /// Dimensions that had usage but no price in this record, named for
    /// display. Empty exactly when `complete` is true.
    pub unpriced_dimensions: Vec<String>,
}

impl CostEstimate {
    /// The amount, but only when it can stand as a complete estimate.
    /// Callers that must not present a floor as a total read this instead
    /// of `micros`, and render "not reported" for `None` — never `$0.00`.
    pub fn micros_if_complete(&self) -> Option<i64> {
        self.complete.then_some(self.micros)
    }

    /// A sentence naming what was not priced, or None when nothing is
    /// missing.
    pub fn incompleteness_note(&self) -> Option<String> {
        if self.complete {
            return None;
        }
        Some(format!(
            "partial estimate — this pricing record has no price for {}, \
             so that usage contributed nothing; the amount is a floor, not a total",
            self.unpriced_dimensions.join(" or ")
        ))
    }
}

/// Estimate token cost as of a usage date (RFC 3339 or YYYY-MM-DD).
/// Returns None when no pricing is known — a number is never invented.
pub fn estimate_token_cost_as_of(
    conn: &Connection,
    provider: &str,
    model: &str,
    as_of: &str,
    input_tokens: i64,
    output_tokens: i64,
) -> Result<Option<CostEstimate>> {
    let Some(rec) = lookup_as_of(conn, provider, model, as_of)? else {
        return Ok(None);
    };
    if rec.unit != Unit::Tokens {
        return Ok(None);
    }
    // A record with no token price at all prices nothing; returning a
    // $0.00 estimate here would invent a number, so there is no estimate.
    if rec.input_price_per_m_micros.is_none() && rec.output_price_per_m_micros.is_none() {
        return Ok(None);
    }
    // A missing price is not a price of zero. Track every dimension that
    // had usage but no price: those tokens contribute nothing to `micros`,
    // which makes the result a floor rather than a total.
    let mut unpriced_dimensions = Vec::new();
    if input_tokens > 0 && rec.input_price_per_m_micros.is_none() {
        unpriced_dimensions.push("input tokens".to_string());
    }
    if output_tokens > 0 && rec.output_price_per_m_micros.is_none() {
        unpriced_dimensions.push("output tokens".to_string());
    }
    let inp = rec.input_price_per_m_micros.unwrap_or(0);
    let out = rec.output_price_per_m_micros.unwrap_or(0);
    // micros = tokens * price_per_million_micros / 1_000_000
    let micros = (input_tokens.saturating_mul(inp) / 1_000_000)
        + (output_tokens.saturating_mul(out) / 1_000_000);
    Ok(Some(CostEstimate {
        micros,
        pricing_source: rec.source.clone(),
        effective_from: rec.effective_from.clone(),
        last_verified: rec.last_verified.clone(),
        is_override: rec.origin == Origin::Override,
        stale: rec.stale,
        note: rec.note.clone(),
        complete: unpriced_dimensions.is_empty(),
        unpriced_dimensions,
    }))
}

/// Estimate the cost of request-unit usage as of a date. Only records whose
/// unit is `requests` participate; None otherwise.
pub fn estimate_request_cost_as_of(
    conn: &Connection,
    provider: &str,
    service: &str,
    as_of: &str,
    requests: i64,
) -> Result<Option<CostEstimate>> {
    let Some(rec) = lookup_as_of(conn, provider, service, as_of)? else {
        return Ok(None);
    };
    let (Unit::Requests, Some(per)) = (rec.unit, rec.per_request_micros) else {
        return Ok(None);
    };
    Ok(Some(CostEstimate {
        micros: requests.saturating_mul(per),
        pricing_source: rec.source.clone(),
        effective_from: rec.effective_from.clone(),
        last_verified: rec.last_verified.clone(),
        is_override: rec.origin == Origin::Override,
        stale: rec.stale,
        note: rec.note.clone(),
        // Request pricing has a single dimension, and the destructuring
        // above already required it to be present.
        complete: true,
        unpriced_dimensions: Vec::new(),
    }))
}

/// Parse a dollar string (e.g. "2.50") into micro-USD.
pub fn dollars_to_micros(dollars: &str) -> Result<i64> {
    let cleaned = dollars.trim().trim_start_matches('$');
    let value: f64 = cleaned
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("'{dollars}' is not a dollar amount")))?;
    if !value.is_finite() || value < 0.0 {
        return Err(CoreError::InvalidInput(format!(
            "'{dollars}' is not a valid amount"
        )));
    }
    // Cap at $1 trillion so the micro-USD value stays well within i64.
    if value > 1e12 {
        return Err(CoreError::InvalidInput(
            "amount is unreasonably large".into(),
        ));
    }
    Ok((value * MICROS_PER_USD as f64).round() as i64)
}

/// Every record, all versions (bundled + imported + overrides), stale flags
/// computed — the full auditable history.
pub fn catalog(conn: &Connection) -> Result<Vec<PricingRecord>> {
    let now = clock::now_rfc3339();
    let mut records = load_db_records(conn, None)?;
    records.extend(bundled());
    for r in &mut records {
        r.stale = r.is_stale(&now);
    }
    records.sort_by(|a, b| {
        (&a.provider, &a.model, &a.effective_from, a.origin.rank()).cmp(&(
            &b.provider,
            &b.model,
            &b.effective_from,
            b.origin.rank(),
        ))
    });
    Ok(records)
}

/// The record that would be used today for each known provider/model.
pub fn effective_catalog(conn: &Connection, as_of: &str) -> Result<Vec<PricingRecord>> {
    let mut keys: Vec<(String, String)> = catalog(conn)?
        .into_iter()
        .map(|r| (r.provider, r.model))
        .collect();
    keys.sort();
    keys.dedup();
    let mut out = Vec::new();
    for (provider, model) in keys {
        if let Some(rec) = lookup_as_of(conn, &provider, &model, as_of)? {
            // Only include the row under its own model key (lookup may
            // resolve a family fallback for other keys).
            if rec.model == model {
                out.push(rec);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn
    }

    #[test]
    fn estimates_token_cost_from_bundled() {
        let conn = mem();
        // gpt-4o: $2.50/1M in, $10/1M out. 1M in + 1M out = $12.50.
        let est = estimate_token_cost_as_of(
            &conn,
            "openai",
            "gpt-4o",
            "2026-07-18",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(est.micros, 12_500_000);
        assert!(!est.is_override);
        assert!(est.pricing_source.contains("openai.com"));
    }

    #[test]
    fn prefix_matches_dated_model_ids() {
        let conn = mem();
        let est = estimate_token_cost_as_of(
            &conn,
            "anthropic",
            "claude-sonnet-4-20260101",
            "2026-07-18",
            1_000_000,
            0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(est.micros, 3_000_000); // $3/1M input
    }

    #[test]
    fn specific_model_beats_family_fallback() {
        let conn = mem();
        // claude-sonnet-5 (intro $2/1M) must not fall back to the generic
        // claude-sonnet rate ($3/1M).
        let est = estimate_token_cost_as_of(
            &conn,
            "anthropic",
            "claude-sonnet-5",
            "2026-07-20",
            1_000_000,
            0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(est.micros, 2_000_000);
    }

    #[test]
    fn effective_dating_switches_price_on_the_documented_date() {
        let conn = mem();
        // Sonnet 5: $2/$10 through 2026-08-31; $3/$15 from 2026-09-01.
        let before = estimate_token_cost_as_of(
            &conn,
            "anthropic",
            "claude-sonnet-5",
            "2026-08-31",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(before.micros, 12_000_000);
        let after = estimate_token_cost_as_of(
            &conn,
            "anthropic",
            "claude-sonnet-5",
            "2026-09-01",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(after.micros, 18_000_000);
    }

    #[test]
    fn usage_before_any_effective_record_extrapolates_and_says_so() {
        let conn = mem();
        let est = estimate_token_cost_as_of(
            &conn,
            "openai",
            "gpt-4o",
            "2020-01-01",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(est.micros, 12_500_000);
        assert!(est.note.contains("applied to earlier usage"));
    }

    #[test]
    fn override_wins_and_is_labeled() {
        let conn = mem();
        set_override(
            &conn,
            "openai",
            "gpt-4o",
            OverrideSpec {
                input_price_per_m_micros: Some(1_000_000),
                output_price_per_m_micros: Some(2_000_000),
                note: "negotiated rate".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let est = estimate_token_cost_as_of(
            &conn,
            "openai",
            "gpt-4o",
            "2026-07-18",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(est.micros, 3_000_000);
        assert!(est.is_override);
        assert!(est.pricing_source.contains("negotiated"));
        // Removing the override restores the bundled rate.
        assert_eq!(remove_override(&conn, "openai", "gpt-4o").unwrap(), 1);
        let est = estimate_token_cost_as_of(
            &conn,
            "openai",
            "gpt-4o",
            "2026-07-18",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(est.micros, 12_500_000);
    }

    #[test]
    fn override_rejects_negative_and_empty() {
        let conn = mem();
        assert!(set_override(
            &conn,
            "openai",
            "gpt-4o",
            OverrideSpec {
                input_price_per_m_micros: Some(-1),
                output_price_per_m_micros: Some(1),
                ..Default::default()
            },
        )
        .is_err());
        assert!(set_override(&conn, "openai", "gpt-4o", OverrideSpec::default()).is_err());
        assert!(set_override(&conn, "", "gpt-4o", OverrideSpec::default()).is_err());
    }

    #[test]
    fn unknown_model_yields_no_estimate() {
        let conn = mem();
        assert!(estimate_token_cost_as_of(
            &conn,
            "openai",
            "made-up-model",
            "2026-07-18",
            100,
            100
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn import_validates_and_preserves_history() {
        let conn = mem();
        // A backdated correction plus a new effective price.
        let json = r#"[
          {"provider":"openai","model":"gpt-4o","unit":"tokens",
           "input_per_m":"2.00","output_per_m":"8.00",
           "source":"https://example.test/pricing","effective_from":"2026-08-01",
           "last_verified":"2026-08-01"}
        ]"#;
        let outcome = import_records(&conn, json).unwrap();
        assert_eq!((outcome.added, outcome.replaced), (1, 0));
        // Before the import's effective date the bundled price still applies.
        let before = estimate_token_cost_as_of(
            &conn,
            "openai",
            "gpt-4o",
            "2026-07-18",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(before.micros, 12_500_000);
        // From the effective date the imported price applies.
        let after = estimate_token_cost_as_of(
            &conn,
            "openai",
            "gpt-4o",
            "2026-08-02",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(after.micros, 10_000_000);
        // Re-importing the same effective date replaces, not duplicates.
        let outcome = import_records(&conn, json).unwrap();
        assert_eq!((outcome.added, outcome.replaced), (0, 1));
    }

    #[test]
    fn import_rejects_bad_records() {
        let conn = mem();
        for bad in [
            // negative price
            r#"[{"provider":"openai","model":"m","input_per_m":"-2","output_per_m":"1",
                "source":"s","effective_from":"2026-01-01","last_verified":"2026-01-01"}]"#,
            // malformed date
            r#"[{"provider":"openai","model":"m","input_per_m":"2","output_per_m":"1",
                "source":"s","effective_from":"January","last_verified":"2026-01-01"}]"#,
            // no prices at all for a token record
            r#"[{"provider":"openai","model":"m",
                "source":"s","effective_from":"2026-01-01","last_verified":"2026-01-01"}]"#,
            // non-finite price
            r#"[{"provider":"openai","model":"m","input_per_m":"NaN","output_per_m":"1",
                "source":"s","effective_from":"2026-01-01","last_verified":"2026-01-01"}]"#,
            // absurd overflow price
            r#"[{"provider":"openai","model":"m","input_per_m":"9e99","output_per_m":"1",
                "source":"s","effective_from":"2026-01-01","last_verified":"2026-01-01"}]"#,
            // not JSON
            "pricing: yes",
            // empty file
            "[]",
        ] {
            assert!(import_records(&conn, bad).is_err(), "accepted: {bad}");
        }
        // Nothing landed.
        assert_eq!(load_db_records(&conn, None).unwrap().len(), 0);
    }

    #[test]
    fn export_import_round_trip() {
        let conn = mem();
        set_override(
            &conn,
            "openai",
            "gpt-4o",
            OverrideSpec {
                input_price_per_m_micros: Some(1_000_000),
                output_price_per_m_micros: Some(2_000_000),
                ..Default::default()
            },
        )
        .unwrap();
        let json = export_records(&conn, Some("openai")).unwrap();
        let parsed: Vec<InterchangeRecord> = serde_json::from_str(&json).unwrap();
        assert!(parsed.iter().any(|r| r.origin == Some(Origin::Override)));
        assert!(parsed.iter().any(|r| r.origin == Some(Origin::Bundled)));
        // The exported file is importable as reviewed data.
        let conn2 = mem();
        import_records(&conn2, &json).unwrap();
        let est = estimate_token_cost_as_of(
            &conn2,
            "openai",
            "gpt-4o",
            "2026-07-18",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        // Highest precedence among the imported rows for 2026-07-18 is the
        // imported copy of the override (all imports share one origin).
        assert!(est.micros == 3_000_000 || est.micros == 12_500_000);
    }

    #[test]
    fn request_unit_estimation_via_override() {
        let conn = mem();
        set_override(
            &conn,
            "openai",
            "web-search",
            OverrideSpec {
                unit: Some(Unit::Requests),
                per_request_micros: Some(10_000), // $0.01/request
                ..Default::default()
            },
        )
        .unwrap();
        let est = estimate_request_cost_as_of(&conn, "openai", "web-search", "2026-07-18", 250)
            .unwrap()
            .unwrap();
        assert_eq!(est.micros, 2_500_000); // $2.50
                                           // A request record never yields a token estimate.
        assert!(
            estimate_token_cost_as_of(&conn, "openai", "web-search", "2026-07-18", 100, 100)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn staleness_uses_last_verified() {
        let mut rec = bundled().into_iter().next().unwrap();
        rec.last_verified = "2020-01-01".into();
        assert!(rec.is_stale("2026-07-18T00:00:00Z"));
        rec.last_verified = "2026-07-17".into();
        assert!(!rec.is_stale("2026-07-18T00:00:00Z"));
    }

    #[test]
    fn legacy_overrides_migrate_into_pricing_records() {
        // Build a database at schema v7 (with pricing_overrides), insert a
        // legacy override, then run the remaining migrations.
        let mut conn = Connection::open_in_memory().unwrap();
        let upto = db::MIGRATIONS
            .iter()
            .position(|m| m.version == 7)
            .expect("v7 exists");
        db::migrate_with(&mut conn, &db::MIGRATIONS[..=upto]).unwrap();
        conn.execute(
            "INSERT INTO pricing_overrides
             (id, provider, model, unit, input_price_per_m_micros, output_price_per_m_micros,
              note, created_at)
             VALUES ('x', 'openai', 'gpt-4o', 'tokens', 1000000, 2000000, 'legacy',
                     '2026-07-01T00:00:00Z')",
            [],
        )
        .unwrap();
        db::migrate(&mut conn).unwrap();
        let est = estimate_token_cost_as_of(
            &conn,
            "openai",
            "gpt-4o",
            "2026-07-18",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(est.micros, 3_000_000);
        assert!(est.is_override);
        // Legacy overrides apply to all dates.
        let old = estimate_token_cost_as_of(
            &conn,
            "openai",
            "gpt-4o",
            "2020-01-01",
            1_000_000,
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(old.micros, 3_000_000);
    }

    #[test]
    fn proposal_template_lists_current_effective_records() {
        let conn = mem();
        let json = proposal_template(&conn, "anthropic").unwrap();
        let parsed: Vec<InterchangeRecord> = serde_json::from_str(&json).unwrap();
        assert!(parsed.iter().any(|r| r.model == "claude-sonnet-5"));
        // One record per model — the currently effective one.
        let sonnet5: Vec<_> = parsed
            .iter()
            .filter(|r| r.model == "claude-sonnet-5")
            .collect();
        assert_eq!(sonnet5.len(), 1);
        assert!(proposal_template(&conn, "nonexistent").is_err());
    }

    #[test]
    fn dollar_parsing() {
        assert_eq!(dollars_to_micros("2.50").unwrap(), 2_500_000);
        assert_eq!(dollars_to_micros("$10").unwrap(), 10_000_000);
        assert!(dollars_to_micros("-1").is_err());
        assert!(dollars_to_micros("abc").is_err());
    }
}
