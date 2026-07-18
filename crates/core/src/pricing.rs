//! Versioned pricing model and cost estimation.
//!
//! Providers do not expose pricing through their APIs, so pricing is a local,
//! versioned record: a small bundled table of published rates (each with its
//! source URL and retrieval date) plus user manual overrides. Estimated costs
//! are always labeled "estimated" and distinguished from provider-reported
//! costs. Records past a staleness horizon are flagged so figures are never
//! silently trusted. Prices are integer micro-USD per one million tokens (or
//! per request), avoiding float rounding.

use crate::clock;
use crate::error::{CoreError, Result};
use crate::usage::MICROS_PER_USD;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use uuid::Uuid;

/// Records retrieved more than this many days ago are flagged stale.
pub const STALE_AFTER_DAYS: i64 = 45;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Tokens,
    Requests,
    Credits,
}

/// A pricing record (bundled or override).
#[derive(Debug, Clone, Serialize)]
pub struct PricingRecord {
    pub provider: String,
    pub model: String,
    pub unit: Unit,
    /// Price per 1,000,000 input tokens, in micro-USD (token pricing).
    pub input_price_per_m_micros: Option<i64>,
    pub output_price_per_m_micros: Option<i64>,
    /// Price per request, in micro-USD (request pricing).
    pub per_request_micros: Option<i64>,
    pub currency: String,
    pub source: String,
    pub effective_date: String,
    pub retrieval_date: String,
    pub is_override: bool,
}

impl PricingRecord {
    pub fn is_stale(&self, now: &str) -> bool {
        let Ok(retrieved) = clock::parse_user_date(&self.retrieval_date) else {
            return true;
        };
        let Ok(now_t) = clock::parse_rfc3339(now) else {
            return false;
        };
        (now_t - retrieved).whole_days() > STALE_AFTER_DAYS
    }
}

/// Bundled published rates. These are ESTIMATES with a source and retrieval
/// date; users should verify against the provider's pricing page and override
/// locally. Prices are per 1M tokens in micro-USD (USD * 1_000_000).
fn bundled() -> Vec<PricingRecord> {
    // Retrieval date for the bundled set. Staleness is measured from here.
    const RETRIEVED: &str = "2026-07-18";
    let rec = |provider: &str, model: &str, inp: i64, out: i64, source: &str| PricingRecord {
        provider: provider.to_string(),
        model: model.to_string(),
        unit: Unit::Tokens,
        input_price_per_m_micros: Some(inp),
        output_price_per_m_micros: Some(out),
        per_request_micros: None,
        currency: "USD".to_string(),
        source: source.to_string(),
        effective_date: RETRIEVED.to_string(),
        retrieval_date: RETRIEVED.to_string(),
        is_override: false,
    };
    vec![
        rec(
            "openai",
            "gpt-4o",
            2_500_000,
            10_000_000,
            "https://openai.com/api/pricing/",
        ),
        rec(
            "openai",
            "gpt-4o-mini",
            150_000,
            600_000,
            "https://openai.com/api/pricing/",
        ),
        rec(
            "openai",
            "o4-mini",
            1_100_000,
            4_400_000,
            "https://openai.com/api/pricing/",
        ),
        rec(
            "anthropic",
            "claude-sonnet",
            3_000_000,
            15_000_000,
            "https://www.anthropic.com/pricing",
        ),
        rec(
            "anthropic",
            "claude-haiku",
            800_000,
            4_000_000,
            "https://www.anthropic.com/pricing",
        ),
    ]
}

/// Look up a pricing record: a manual override wins over the bundled set.
/// Model matching is case-insensitive and falls back to a prefix match so
/// dated model ids (e.g. `claude-sonnet-4-20250514`) resolve to a base rate.
pub fn lookup(conn: &Connection, provider: &str, model: &str) -> Result<Option<PricingRecord>> {
    let provider = provider.to_lowercase();
    let model_l = model.to_lowercase();

    // 1. Exact override.
    if let Some(o) = load_override(conn, &provider, &model_l)? {
        return Ok(Some(o));
    }
    // 2. Exact bundled.
    if let Some(b) = bundled()
        .into_iter()
        .find(|r| r.provider == provider && r.model.eq_ignore_ascii_case(&model_l))
    {
        return Ok(Some(b));
    }
    // 3. Prefix bundled (dated/variant model ids).
    if let Some(b) = bundled()
        .into_iter()
        .find(|r| r.provider == provider && model_l.contains(&r.model))
    {
        return Ok(Some(b));
    }
    Ok(None)
}

fn load_override(conn: &Connection, provider: &str, model: &str) -> Result<Option<PricingRecord>> {
    let row = conn
        .query_row(
            "SELECT provider, model, unit, input_price_per_m_micros, output_price_per_m_micros,
                    currency, note, created_at
             FROM pricing_overrides WHERE provider = ?1 AND model = ?2 COLLATE NOCASE",
            params![provider, model],
            |r| {
                Ok(PricingRecord {
                    provider: r.get(0)?,
                    model: r.get(1)?,
                    unit: match r.get::<_, String>(2)?.as_str() {
                        "requests" => Unit::Requests,
                        "credits" => Unit::Credits,
                        _ => Unit::Tokens,
                    },
                    input_price_per_m_micros: r.get(3)?,
                    output_price_per_m_micros: r.get(4)?,
                    per_request_micros: None,
                    currency: r.get(5)?,
                    source: format!("manual override ({})", r.get::<_, String>(6)?),
                    effective_date: r.get::<_, String>(7)?,
                    retrieval_date: r.get::<_, String>(7)?,
                    is_override: true,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// Set (or replace) a manual pricing override.
pub fn set_override(
    conn: &Connection,
    provider: &str,
    model: &str,
    input_price_per_m_micros: i64,
    output_price_per_m_micros: i64,
    note: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pricing_overrides
         (id, provider, model, unit, input_price_per_m_micros, output_price_per_m_micros, note, created_at)
         VALUES (?1, ?2, ?3, 'tokens', ?4, ?5, ?6, ?7)
         ON CONFLICT(provider, model) DO UPDATE SET
           input_price_per_m_micros = excluded.input_price_per_m_micros,
           output_price_per_m_micros = excluded.output_price_per_m_micros,
           note = excluded.note, created_at = excluded.created_at",
        params![
            Uuid::new_v4().to_string(),
            provider.to_lowercase(),
            model.to_lowercase(),
            input_price_per_m_micros,
            output_price_per_m_micros,
            note,
            clock::now_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn list_overrides(conn: &Connection) -> Result<Vec<PricingRecord>> {
    let mut stmt =
        conn.prepare("SELECT provider, model FROM pricing_overrides ORDER BY provider, model")?;
    let keys: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Vec::new();
    for (p, m) in keys {
        if let Some(r) = load_override(conn, &p, &m)? {
            out.push(r);
        }
    }
    Ok(out)
}

/// The outcome of estimating a cost.
#[derive(Debug, Clone, Serialize)]
pub struct CostEstimate {
    pub micros: i64,
    pub pricing_source: String,
    pub retrieval_date: String,
    pub is_override: bool,
    pub stale: bool,
}

/// Estimate token cost. Returns None when no pricing is known (so callers can
/// avoid inventing a number).
pub fn estimate_token_cost(
    conn: &Connection,
    provider: &str,
    model: &str,
    input_tokens: i64,
    output_tokens: i64,
) -> Result<Option<CostEstimate>> {
    let Some(rec) = lookup(conn, provider, model)? else {
        return Ok(None);
    };
    let inp = rec.input_price_per_m_micros.unwrap_or(0);
    let out = rec.output_price_per_m_micros.unwrap_or(0);
    // micros = tokens * price_per_million_micros / 1_000_000
    let micros = (input_tokens.saturating_mul(inp) / 1_000_000)
        + (output_tokens.saturating_mul(out) / 1_000_000);
    Ok(Some(CostEstimate {
        micros,
        pricing_source: rec.source.clone(),
        retrieval_date: rec.retrieval_date.clone(),
        is_override: rec.is_override,
        stale: rec.is_stale(&clock::now_rfc3339()),
    }))
}

/// Parse a dollar string (e.g. "2.50") into micro-USD.
pub fn dollars_to_micros(dollars: &str) -> Result<i64> {
    let cleaned = dollars.trim().trim_start_matches('$');
    let value: f64 = cleaned
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("'{dollars}' is not a dollar amount")))?;
    if value < 0.0 {
        return Err(CoreError::InvalidInput(
            "amount must not be negative".into(),
        ));
    }
    Ok((value * MICROS_PER_USD as f64).round() as i64)
}

/// The full catalog (bundled + overrides), for display.
pub fn catalog(conn: &Connection) -> Result<Vec<PricingRecord>> {
    let mut records = list_overrides(conn)?;
    for b in bundled() {
        // Skip a bundled record shadowed by an override.
        if !records
            .iter()
            .any(|o| o.provider == b.provider && o.model.eq_ignore_ascii_case(&b.model))
        {
            records.push(b);
        }
    }
    Ok(records)
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
        let est = estimate_token_cost(&conn, "openai", "gpt-4o", 1_000_000, 1_000_000)
            .unwrap()
            .unwrap();
        assert_eq!(est.micros, 12_500_000);
        assert!(!est.is_override);
        assert!(est.pricing_source.contains("openai.com"));
    }

    #[test]
    fn prefix_matches_dated_model_ids() {
        let conn = mem();
        let est = estimate_token_cost(&conn, "anthropic", "claude-sonnet-4-20260101", 1_000_000, 0)
            .unwrap()
            .unwrap();
        assert_eq!(est.micros, 3_000_000); // $3/1M input
    }

    #[test]
    fn override_wins_and_is_labeled() {
        let conn = mem();
        set_override(
            &conn,
            "openai",
            "gpt-4o",
            1_000_000,
            2_000_000,
            "negotiated rate",
        )
        .unwrap();
        let est = estimate_token_cost(&conn, "openai", "gpt-4o", 1_000_000, 1_000_000)
            .unwrap()
            .unwrap();
        assert_eq!(est.micros, 3_000_000);
        assert!(est.is_override);
        assert!(est.pricing_source.contains("negotiated"));
    }

    #[test]
    fn unknown_model_yields_no_estimate() {
        let conn = mem();
        assert!(
            estimate_token_cost(&conn, "openai", "made-up-model", 100, 100)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn staleness_uses_retrieval_date() {
        let mut rec = bundled().into_iter().next().unwrap();
        rec.retrieval_date = "2020-01-01".into();
        assert!(rec.is_stale("2026-07-18T00:00:00Z"));
        rec.retrieval_date = "2026-07-17".into();
        assert!(!rec.is_stale("2026-07-18T00:00:00Z"));
    }

    #[test]
    fn dollar_parsing() {
        assert_eq!(dollars_to_micros("2.50").unwrap(), 2_500_000);
        assert_eq!(dollars_to_micros("$10").unwrap(), 10_000_000);
        assert!(dollars_to_micros("-1").is_err());
        assert!(dollars_to_micros("abc").is_err());
    }
}
