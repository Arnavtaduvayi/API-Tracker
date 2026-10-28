//! The usage publisher (Increment 06, DESIGN §D14): turns this device's
//! gateway-observed daily usage into replicated, deletion-aware counters.
//!
//! **Source.** `gateway_usage_daily` rows of local projects bound to a mesh
//! project. Rows of unattributed traffic (`project_id = ''`) are never
//! published. A row whose response named no model (`model = ''`, which the
//! writer stores for it) is real, unpriced traffic and is published under the
//! model label [`UNKNOWN_MODEL`], not dropped.
//!
//! **Totals.** `requests`, the honesty split, tokens, and the estimate (priced
//! requests only; computed here, at ingest, with this device's pricing).
//! Rows the writer created before migration v23 (`split_known = 0`) cannot
//! tell priced from unpriced: they publish `unextracted` (always known, as
//! `request_count - usage_event_count`) and leave priced and unpriced at 0,
//! so `requests - priced - unpriced - unextracted` is the honest "split
//! unknown" remainder views show.
//!
//! **Deltas through a cursor.** `mesh_publish_cursor` records, per local row
//! and per mesh project, what was attributed so far. A run adds `now -
//! attributed` to the counter of the mesh project the local project is bound
//! to **now**, so a rebind moves only later traffic. If a local row shrank or
//! vanished (`delete_project_data`, `delete_all`, the retention sweep), every
//! attribution of it is taken back from the counter it went to, with an
//! **epoch bump** (the owner-counter lattice: a higher epoch wins outright),
//! so the deletion reaches every device instead of being "resurrected" by a
//! max. The counters and the cursor change in one transaction.
//!
//! **Bounds.** At most [`HOURLY_BUDGET`] counters an hour (peers accept 10 000
//! items an hour from one origin), oldest days first; the rest wait for the
//! next run, which `node/publish` in `mesh_meta` records.
//!
//! **Retention.** The LWW `mesh.setting` [`RETENTION_SETTING`] (default 90
//! days): days older are never published; two days later still, counters are
//! dropped at ingest and garbage-collected on every device.

use super::dot::{DeviceId, MeshProjectId};
use super::kinds::{Day, UsageCounter, UsageKey, UsageTotals};
use super::projects;
use super::sign::SigningKeyPair;
use super::sqlite_store::SqliteStore;
use super::store::{Draft, HlcPolicy, MeshStore};
use crate::error::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RETENTION_SETTING: &str = "retention.usage_days";
pub const DEFAULT_RETENTION_DAYS: u64 = 90;
pub const MAX_RETENTION_DAYS: u64 = 3650;
/// Counters published per UTC hour at most.
pub const HOURLY_BUDGET: u64 = 5_000;
/// Days past the horizon before counters are dropped and collected, so two
/// devices whose clocks straddle midnight agree on what they hold.
pub const GC_LAG_DAYS: u64 = 2;
/// The model label of traffic whose response named no model.
pub const UNKNOWN_MODEL: &str = "(not reported)";
const DAY_MS: u64 = 86_400_000;

/// What one run did (also kept as `node/publish` in `mesh_meta`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishReport {
    pub at_ms: u64,
    /// Counters minted this run.
    pub minted: u64,
    /// Counters with changes left for a later run (the hourly budget).
    pub deferred: u64,
    /// Counters whose epoch was bumped (local data was deleted).
    pub epoch_bumps: u64,
    /// Usage counters removed for being past the retention horizon.
    pub collected: u64,
    pub retention_days: u64,
    /// The hour (`at_ms / 3_600_000`) and how many were minted in it.
    pub hour: u64,
    pub minted_this_hour: u64,
}

/// The retention horizon in days: the LWW setting, if it is a sane number.
pub fn retention_days(store: &SqliteStore) -> u64 {
    let state = store.state();
    state
        .settings
        .value(&RETENTION_SETTING.to_owned(), &state.roster)
        .and_then(serde_json::Value::as_u64)
        .filter(|d| (1..=MAX_RETENTION_DAYS).contains(d))
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

/// The first day still inside the horizon at `now_ms`.
pub fn horizon_start(store: &SqliteStore, now_ms: u64) -> Day {
    Day::from_unix_ms(now_ms.saturating_sub(retention_days(store) * DAY_MS))
}

/// Set the store's ingest floor from the horizon and collect what fell out.
pub fn apply_retention(store: &mut SqliteStore, now_ms: u64) -> Result<u64> {
    let floor =
        Day::from_unix_ms(now_ms.saturating_sub((retention_days(store) + GC_LAG_DAYS) * DAY_MS));
    store.set_usage_floor(Some(floor));
    Ok(store.gc_usage()? as u64)
}

/// One local daily row, as totals.
fn row_totals(r: &rusqlite::Row<'_>) -> rusqlite::Result<UsageTotals> {
    let n = |i: usize| -> rusqlite::Result<u64> { Ok(r.get::<_, i64>(i)?.max(0) as u64) };
    let requests = n(4)?;
    let with_usage = n(5)?;
    let split_known = r.get::<_, i64>(8)? == 1;
    let (unpriced, unextracted) = if split_known {
        (n(6)?, n(7)?)
    } else {
        (0, requests.saturating_sub(with_usage))
    };
    let priced = if split_known {
        requests.saturating_sub(unpriced + unextracted)
    } else {
        0
    };
    Ok(UsageTotals {
        requests,
        priced_requests: priced,
        unpriced_requests: unpriced,
        unextracted_requests: unextracted,
        input_tokens: n(9)?,
        output_tokens: n(10)?,
        cached_input_tokens: n(11)?,
        estimated_cost_micros: n(12)?,
    })
}

/// `(local project, day, provider, model)`.
type LocalKey = (String, Day, String, String);

fn local_rows(
    conn: &Connection,
    locals: &BTreeSet<String>,
    since: Day,
) -> Result<BTreeMap<LocalKey, UsageTotals>> {
    let mut st = conn.prepare(
        "SELECT project_id, day, provider_id, model, request_count, usage_event_count,
                unpriced_requests, unextracted_requests, split_known, input_tokens,
                output_tokens, cached_input_tokens, estimated_cost_micros
         FROM gateway_usage_daily
         WHERE project_id <> '' AND provider_id <> '' AND day >= ?1",
    )?;
    let rows = st.query_map([since.to_string()], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            row_totals(r)?,
        ))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (p, d, prov, model, t) = row?;
        if !locals.contains(&p) {
            continue;
        }
        let Some(day) = Day::parse(&d) else { continue };
        let model = if model.is_empty() {
            UNKNOWN_MODEL.to_owned()
        } else {
            model
        };
        let e: &mut UsageTotals = out.entry((p, day, prov, model)).or_default();
        *e = add(e, &t);
    }
    Ok(out)
}

/// `(local key, mesh project)` → what was attributed.
type Cursor = BTreeMap<(LocalKey, MeshProjectId), UsageTotals>;

fn cursor_rows(conn: &Connection) -> Result<Cursor> {
    let mut st = conn.prepare(
        "SELECT local_project_id, mesh_project_id, day, provider_id, model, requests,
                priced_requests, unpriced_requests, unextracted_requests, input_tokens,
                output_tokens, cached_input_tokens, estimated_cost_micros
         FROM mesh_publish_cursor",
    )?;
    let rows = st.query_map([], |r| {
        let n = |i: usize| -> rusqlite::Result<u64> { Ok(r.get::<_, i64>(i)?.max(0) as u64) };
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            UsageTotals {
                requests: n(5)?,
                priced_requests: n(6)?,
                unpriced_requests: n(7)?,
                unextracted_requests: n(8)?,
                input_tokens: n(9)?,
                output_tokens: n(10)?,
                cached_input_tokens: n(11)?,
                estimated_cost_micros: n(12)?,
            },
        ))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (l, m, d, p, model, t) = row?;
        let (Ok(m), Some(day)) = (MeshProjectId::parse(&m), Day::parse(&d)) else {
            continue;
        };
        out.insert(((l, day, p, model), m), t);
    }
    Ok(out)
}

fn zip(a: &UsageTotals, b: &UsageTotals, f: impl Fn(u64, u64) -> u64) -> UsageTotals {
    UsageTotals {
        requests: f(a.requests, b.requests),
        priced_requests: f(a.priced_requests, b.priced_requests),
        unpriced_requests: f(a.unpriced_requests, b.unpriced_requests),
        unextracted_requests: f(a.unextracted_requests, b.unextracted_requests),
        input_tokens: f(a.input_tokens, b.input_tokens),
        output_tokens: f(a.output_tokens, b.output_tokens),
        cached_input_tokens: f(a.cached_input_tokens, b.cached_input_tokens),
        estimated_cost_micros: f(a.estimated_cost_micros, b.estimated_cost_micros),
    }
}

pub fn add(a: &UsageTotals, b: &UsageTotals) -> UsageTotals {
    zip(a, b, u64::saturating_add)
}

fn sub(a: &UsageTotals, b: &UsageTotals) -> UsageTotals {
    zip(a, b, u64::saturating_sub)
}

/// Every field of `a` at least that of `b`.
fn covers(a: &UsageTotals, b: &UsageTotals) -> bool {
    sub(b, a) == UsageTotals::default()
}

/// A counter's pending change.
#[derive(Default)]
struct Change {
    add: UsageTotals,
    take: UsageTotals,
    bump: bool,
}

fn publish_gen(conn: &Connection) -> Result<i64> {
    Ok(conn
        .query_row(
            "SELECT value FROM mesh_meta WHERE key = 'publish/gen'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0))
}

/// Run the publisher once: retention, then deltas for every bound local
/// project, minted with the cursor in one transaction. Two publishers on one
/// database (a running node and a CLI command) cannot both attribute one
/// delta: the transaction checks that no other run committed since this one
/// read the cursor (`publish/gen`), and on a conflict the run starts over.
pub fn publish(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    now_ms: u64,
) -> Result<PublishReport> {
    publish_with_budget(store, signing, now_ms, HOURLY_BUDGET)
}

/// [`publish`] with another hourly budget (tests use a small one).
pub fn publish_with_budget(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    now_ms: u64,
    hourly_budget: u64,
) -> Result<PublishReport> {
    let mut last = None;
    for _ in 0..3 {
        match publish_once(store, signing, now_ms, hourly_budget) {
            Err(crate::error::CoreError::Mesh(super::MeshError::Storage(PUBLISH_CONFLICT))) => {
                last = Some(super::MeshError::Storage(PUBLISH_CONFLICT));
            }
            other => return other,
        }
    }
    Err(last.expect("set by the loop").into())
}

const PUBLISH_CONFLICT: &str = "another publisher ran at the same time";

fn publish_once(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    now_ms: u64,
    hourly_budget: u64,
) -> Result<PublishReport> {
    let mut report = PublishReport {
        at_ms: now_ms,
        retention_days: retention_days(store),
        hour: now_ms / 3_600_000,
        ..Default::default()
    };
    report.collected = apply_retention(store, now_ms)?;
    let since = horizon_start(store, now_ms);
    let me = store.self_id();
    let previous = last_report(store.connection())?;
    let used = previous
        .filter(|p| p.hour == report.hour)
        .map_or(0, |p| p.minted_this_hour);
    let mut budget = hourly_budget.saturating_sub(used);

    let gen = publish_gen(store.connection())?;
    let bound = projects::bindings(store.connection())?;
    let locals: BTreeSet<String> = bound.keys().cloned().collect();
    let now_rows = local_rows(store.connection(), &locals, since)?;
    let cursor = cursor_rows(store.connection())?;

    // Every local key with a row now, or with something attributed.
    let mut keys: BTreeSet<LocalKey> = now_rows.keys().cloned().collect();
    keys.extend(cursor.keys().map(|(k, _)| k.clone()));
    // Oldest days first, so a deferred remainder is the newest.
    let mut keys: Vec<LocalKey> = keys.into_iter().collect();
    keys.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.cmp(b)));

    let mut changes: BTreeMap<UsageKey, Change> = BTreeMap::new();
    let mut new_cursor: Vec<((LocalKey, MeshProjectId), Option<UsageTotals>)> = Vec::new();
    let mut stale_cursor: Vec<(LocalKey, MeshProjectId)> = Vec::new();
    for k in keys {
        let parts: Vec<(MeshProjectId, UsageTotals)> = cursor
            .range((k.clone(), MeshProjectId::MIN)..=(k.clone(), MeshProjectId::MAX))
            .map(|((_, m), t)| (*m, *t))
            .collect();
        if k.1 < since {
            // Past the horizon: never published again; forget the cursor.
            stale_cursor.extend(parts.iter().map(|(m, _)| (k.clone(), *m)));
            continue;
        }
        let now = now_rows.get(&k).copied().unwrap_or_default();
        let attributed = parts
            .iter()
            .fold(UsageTotals::default(), |acc, (_, t)| add(&acc, t));
        let target = bound.get(&k.0).copied();
        if now == attributed {
            continue;
        }
        let counter = |m: MeshProjectId| UsageKey {
            project: m,
            day: k.1,
            provider: k.2.clone(),
            model: k.3.clone(),
        };
        // The counters this key touches; it is all or nothing.
        let mut touched: BTreeSet<UsageKey> = BTreeSet::new();
        if covers(&now, &attributed) {
            let Some(m) = target else {
                continue; // unbound since: nothing new is attributed
            };
            touched.insert(counter(m));
        } else {
            touched.extend(parts.iter().map(|(m, _)| counter(*m)));
            if let Some(m) = target {
                touched.insert(counter(m));
            }
        }
        let new_counters = touched.iter().filter(|c| !changes.contains_key(c)).count() as u64;
        if new_counters > budget {
            report.deferred += new_counters;
            continue;
        }
        budget -= new_counters;
        if covers(&now, &attributed) {
            let m = target.expect("checked");
            let delta = sub(&now, &attributed);
            let c = changes.entry(counter(m)).or_default();
            c.add = add(&c.add, &delta);
            let mine = cursor.get(&(k.clone(), m)).copied().unwrap_or_default();
            new_cursor.push(((k.clone(), m), Some(add(&mine, &delta))));
        } else {
            // Local data shrank: take back every part, then attribute what
            // is left to the current binding.
            for (m, t) in &parts {
                let c = changes.entry(counter(*m)).or_default();
                c.take = add(&c.take, t);
                c.bump = true;
                new_cursor.push(((k.clone(), *m), None));
            }
            if let (Some(m), false) = (target, now == UsageTotals::default()) {
                let c = changes.entry(counter(m)).or_default();
                c.add = add(&c.add, &now);
                new_cursor.push(((k.clone(), m), Some(now)));
            }
        }
    }

    let mut drafts = Vec::new();
    {
        let state = store.state();
        for (key, ch) in &changes {
            let cur = state.usage.get(key, &me).map(|e| e.value.clone());
            let (epoch, totals) = cur.map_or((0, UsageTotals::default()), |v| (v.epoch, v.totals));
            let totals = add(&sub(&totals, &ch.take), &ch.add);
            let epoch = if ch.bump {
                report.epoch_bumps += 1;
                epoch.saturating_add(1)
            } else {
                epoch
            };
            drafts.push(Draft::of(
                &UsageCounter {
                    key: key.clone(),
                    epoch,
                    totals,
                },
                HlcPolicy::Now,
            ));
        }
    }
    report.minted = drafts.len() as u64;
    report.minted_this_hour = used + report.minted;
    let at = crate::clock::now_rfc3339();
    let record = serde_json::to_string(&report)?;
    store.mint_batch(signing, drafts, |tx| {
        let sql = |_| super::MeshError::Storage("writing the publish cursor");
        let now_gen: i64 = tx
            .query_row(
                "SELECT COALESCE((SELECT value FROM mesh_meta WHERE key = 'publish/gen'), 0)",
                [],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if now_gen != gen {
            return Err(super::MeshError::Storage(PUBLISH_CONFLICT));
        }
        tx.execute(
            "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES ('publish/gen', ?1)",
            [gen + 1],
        )
        .map_err(sql)?;
        for ((k, m), t) in &new_cursor {
            match t {
                None => {
                    tx.execute(
                        "DELETE FROM mesh_publish_cursor WHERE local_project_id = ?1
                         AND mesh_project_id = ?2 AND day = ?3 AND provider_id = ?4
                         AND model = ?5",
                        params![k.0, m.to_hex(), k.1.to_string(), k.2, k.3],
                    )
                    .map_err(sql)?;
                }
                Some(t) => {
                    let i = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
                    tx.execute(
                        "INSERT OR REPLACE INTO mesh_publish_cursor
                            (local_project_id, mesh_project_id, day, provider_id, model,
                             requests, priced_requests, unpriced_requests,
                             unextracted_requests, input_tokens, output_tokens,
                             cached_input_tokens, estimated_cost_micros, updated_at)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                        params![
                            k.0,
                            m.to_hex(),
                            k.1.to_string(),
                            k.2,
                            k.3,
                            i(t.requests),
                            i(t.priced_requests),
                            i(t.unpriced_requests),
                            i(t.unextracted_requests),
                            i(t.input_tokens),
                            i(t.output_tokens),
                            i(t.cached_input_tokens),
                            i(t.estimated_cost_micros),
                            at,
                        ],
                    )
                    .map_err(sql)?;
                }
            }
        }
        for (k, m) in &stale_cursor {
            tx.execute(
                "DELETE FROM mesh_publish_cursor WHERE local_project_id = ?1
                 AND mesh_project_id = ?2 AND day = ?3 AND provider_id = ?4 AND model = ?5",
                params![k.0, m.to_hex(), k.1.to_string(), k.2, k.3],
            )
            .map_err(sql)?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES ('node/publish', ?1)",
            [&record],
        )
        .map_err(sql)?;
        Ok(())
    })?;
    Ok(report)
}

/// The last run's report.
pub fn last_report(conn: &Connection) -> Result<Option<PublishReport>> {
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM mesh_meta WHERE key = 'node/publish'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(v.and_then(|v| serde_json::from_str(&v).ok()))
}

/// This device's own published totals for a counter (tests, status).
pub fn own_counter(store: &SqliteStore, key: &UsageKey) -> Option<(u32, UsageTotals)> {
    let me: DeviceId = store.self_id();
    store
        .state()
        .usage
        .get(key, &me)
        .map(|e| (e.value.epoch, e.value.totals))
}
