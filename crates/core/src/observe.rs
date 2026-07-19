//! Expanded explainable suspicious-activity rules.
//!
//! Every rule works from locally stored evidence (synced usage snapshots,
//! audit events, process sessions, destination state, rotation state) and
//! produces an alert carrying: the rule, the evidence, the comparison
//! window, the attribution precision of the underlying data, a confidence,
//! and a recommended response. No rule claims malice — they describe the
//! observation and what to check.

use crate::alerts::{AlertKind, NewAlert, Severity};
use crate::error::Result;
use crate::providers::Confidence;
use rusqlite::{params, Connection};

fn month_start(now: time::OffsetDateTime) -> String {
    format!("{:04}-{:02}-01T00:00:00Z", now.year(), now.month() as u8)
}

fn previous_month_start(now: time::OffsetDateTime) -> String {
    let (year, month) = match now.month() as u8 {
        1 => (now.year() - 1, 12),
        m => (now.year(), m - 1),
    };
    format!("{year:04}-{month:02}-01T00:00:00Z")
}

fn days_ago(now: time::OffsetDateTime, days: i64) -> String {
    crate::clock::to_rfc3339(now - time::Duration::days(days))
}

/// The kinds this module manages (for monitor auto-resolution).
pub fn managed_kinds() -> Vec<AlertKind> {
    vec![
        AlertKind::RequestSpike,
        AlertKind::CredentialActivated,
        AlertKind::RepeatedAuthFailure,
        AlertKind::NewProviderProject,
        AlertKind::NewProviderKey,
        AlertKind::UnusualModel,
        AlertKind::UnusualTimePattern,
        AlertKind::DestinationDrift,
        AlertKind::RotationAttention,
        AlertKind::AccessGrantExpired,
        AlertKind::PricingStale,
    ]
}

/// Evaluate every rule. `label_of` maps a credential id to its display
/// label (project/name).
pub fn alerts(
    conn: &Connection,
    now: time::OffsetDateTime,
    label_of: &dyn Fn(&str) -> String,
) -> Result<Vec<NewAlert>> {
    let mut out = Vec::new();
    let observed = crate::clock::to_rfc3339(now);
    let this_month = month_start(now);
    let last_month = previous_month_start(now);

    // --- Request spike: attributed request counts, this month vs last.
    {
        let mut stmt = conn.prepare(
            "SELECT credential_id,
                    SUM(CASE WHEN window_start >= ?1 THEN COALESCE(request_count,0) ELSE 0 END),
                    SUM(CASE WHEN window_start >= ?2 AND window_start < ?1
                             THEN COALESCE(request_count,0) ELSE 0 END),
                    MIN(attribution)
             FROM usage_snapshots
             WHERE credential_id IS NOT NULL
             GROUP BY credential_id",
        )?;
        let rows = stmt.query_map(params![this_month, last_month], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (cred, current, previous, attribution) = row?;
            if previous >= 50 && current >= previous.saturating_mul(3) {
                let label = label_of(&cred);
                out.push(NewAlert {
                    kind: AlertKind::RequestSpike,
                    severity: Severity::High,
                    dedup_key: format!("request_spike:{cred}"),
                    title: format!("request spike: {label}"),
                    detail: format!(
                        "recorded requests this calendar month ({current}) are at least 3x \
                         last month's ({previous}). Attribution of the underlying data: \
                         {attribution}."
                    ),
                    evidence: format!(
                        "current_month={current} previous_month={previous} windows=[{last_month} \
                         → now]"
                    ),
                    confidence: Confidence::Medium,
                    recommended_action: "check what started calling this credential; rotate if \
                                         unexplained"
                        .into(),
                    project_id: None,
                    credential_id: Some(cred),
                    observed_at: observed.clone(),
                });
            }
        }
    }

    // --- Previously dormant credential becoming active.
    {
        let recent = days_ago(now, 14);
        let dormant_boundary = days_ago(now, 90);
        let mut stmt = conn.prepare(
            "SELECT u.credential_id, COUNT(*), MIN(u.attribution)
             FROM usage_snapshots u
             JOIN credentials c ON c.id = u.credential_id
             WHERE u.window_start >= ?1
               AND c.created_at < ?2
               AND NOT EXISTS (
                   SELECT 1 FROM usage_snapshots older
                   WHERE older.credential_id = u.credential_id
                     AND older.window_start < ?1 AND older.window_start >= ?2)
               AND EXISTS (
                   SELECT 1 FROM usage_snapshots ancient
                   WHERE ancient.credential_id = u.credential_id
                     AND ancient.window_start < ?2)
             GROUP BY u.credential_id",
        )?;
        let rows = stmt.query_map(params![recent, dormant_boundary], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (cred, rows_new, attribution) = row?;
            let label = label_of(&cred);
            out.push(NewAlert {
                kind: AlertKind::CredentialActivated,
                severity: Severity::Medium,
                dedup_key: format!("credential_activated:{cred}"),
                title: format!("dormant credential became active: {label}"),
                detail: format!(
                    "no recorded usage between 90 and 14 days ago, but {rows_new} usage \
                     record(s) appeared in the last 14 days (data attribution: {attribution})."
                ),
                evidence: format!(
                    "windows: quiet=[{dormant_boundary} → {recent}], active=[{recent} → now], \
                     new_rows={rows_new}"
                ),
                confidence: Confidence::Medium,
                recommended_action: "confirm the new consumer is yours; rotate if not".into(),
                project_id: None,
                credential_id: Some(cred),
                observed_at: observed.clone(),
            });
        }
    }

    // --- Repeated authentication failure (validation failures in 24h).
    {
        let day_ago = days_ago(now, 1);
        let mut stmt = conn.prepare(
            "SELECT credential_id, COUNT(*) FROM audit_events
             WHERE event = 'credential_validated' AND detail LIKE '%valid=false%'
               AND at >= ?1 AND credential_id IS NOT NULL
             GROUP BY credential_id HAVING COUNT(*) >= 3",
        )?;
        let rows = stmt.query_map([&day_ago], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (cred, failures) = row?;
            let label = label_of(&cred);
            out.push(NewAlert {
                kind: AlertKind::RepeatedAuthFailure,
                severity: Severity::High,
                dedup_key: format!("repeated_auth_failure:{cred}"),
                title: format!("repeated validation failures: {label}"),
                detail: format!(
                    "{failures} failed validations in the last 24 hours. The key may be \
                     revoked, rotated at the provider, or mistyped."
                ),
                evidence: format!("failures_24h={failures} since={day_ago}"),
                confidence: Confidence::High,
                recommended_action: "check the key at the provider; update or rotate the \
                                     stored value"
                    .into(),
                project_id: None,
                credential_id: Some(cred),
                observed_at: observed.clone(),
            });
        }
    }

    // --- New provider-side entities (first seen within 7 days).
    {
        let week_ago = days_ago(now, 7);
        let mut stmt = conn.prepare(
            "SELECT provider, project_id, name FROM provider_side_projects
             WHERE first_seen_at >= ?1",
        )?;
        let rows = stmt.query_map([&week_ago], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (provider, project_id, name) = row?;
            out.push(NewAlert {
                kind: AlertKind::NewProviderProject,
                severity: Severity::Info,
                dedup_key: format!("new_provider_project:{provider}:{project_id}"),
                title: format!("new {provider} project appeared: {name}"),
                detail: format!(
                    "provider project '{name}' ({project_id}) was first seen in the last 7 \
                     days. New projects are normal when you created them — this is a \
                     visibility notice, not an accusation."
                ),
                evidence: format!("provider={provider} project_id={project_id}"),
                confidence: Confidence::High,
                recommended_action: "confirm you (or a teammate) created it".into(),
                project_id: None,
                credential_id: None,
                observed_at: observed.clone(),
            });
        }
        let mut stmt = conn.prepare(
            "SELECT provider, api_key_id, name FROM provider_side_keys
             WHERE first_seen_at >= ?1",
        )?;
        let rows = stmt.query_map([&week_ago], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (provider, key_id, name) = row?;
            out.push(NewAlert {
                kind: AlertKind::NewProviderKey,
                severity: Severity::Medium,
                dedup_key: format!("new_provider_key:{provider}:{key_id}"),
                title: format!("new {provider} API key appeared: {name}"),
                detail: format!(
                    "provider-side key '{name}' ({key_id}) was first seen in the last 7 \
                     days. If nobody on your side created it, treat it as suspicious."
                ),
                evidence: format!("provider={provider} api_key_id={key_id}"),
                confidence: Confidence::High,
                recommended_action: "confirm who created it; revoke it at the provider if \
                                     unexplained"
                    .into(),
                project_id: None,
                credential_id: None,
                observed_at: observed.clone(),
            });
        }
    }

    // --- Unusual model: first use of a model in the last 7 days for a
    //     provider with an older usage baseline.
    {
        let week_ago = days_ago(now, 7);
        let month_ago = days_ago(now, 30);
        let mut stmt = conn.prepare(
            "SELECT provider, model, MIN(window_start) FROM usage_snapshots
             WHERE model IS NOT NULL
             GROUP BY provider, model
             HAVING MIN(window_start) >= ?1
                AND EXISTS (
                    SELECT 1 FROM usage_snapshots base
                    WHERE base.provider = usage_snapshots.provider
                      AND base.window_start < ?2)",
        )?;
        let rows = stmt.query_map(params![week_ago, month_ago], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (provider, model, first) = row?;
            out.push(NewAlert {
                kind: AlertKind::UnusualModel,
                severity: Severity::Info,
                dedup_key: format!("unusual_model:{provider}:{model}"),
                title: format!("first use of model '{model}' ({provider})"),
                detail: format!(
                    "usage of '{model}' first appeared on {first}; this provider has usage \
                     history older than 30 days without it. New models are usually a \
                     deliberate change — verify it was yours."
                ),
                evidence: format!("first_window={first} baseline=>30d"),
                confidence: Confidence::Medium,
                recommended_action: "confirm the model change was intentional (it may also \
                                     change costs)"
                    .into(),
                project_id: None,
                credential_id: None,
                observed_at: observed.clone(),
            });
        }
    }

    // --- Unexpected time pattern (LOCAL injection sessions only; provider
    //     buckets are daily and carry no time-of-day signal).
    {
        let week_ago = days_ago(now, 7);
        let mut stmt = conn.prepare(
            "SELECT id, project_id, started_at, strftime('%H', started_at) FROM process_sessions
             WHERE started_at >= ?1
               AND (SELECT COUNT(*) FROM process_sessions all_s
                    WHERE all_s.started_at < ?1) >= 10
               AND NOT EXISTS (
                   SELECT 1 FROM process_sessions prior
                   WHERE prior.started_at < ?1
                     AND strftime('%H', prior.started_at) = strftime('%H', process_sessions.started_at))",
        )?;
        let rows = stmt.query_map([&week_ago], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (session_id, project_id, started_at, hour) = row?;
            out.push(NewAlert {
                kind: AlertKind::UnusualTimePattern,
                severity: Severity::Info,
                dedup_key: format!("unusual_time:{session_id}"),
                title: format!("injection session at an unusual hour ({hour}:00 UTC)"),
                detail: format!(
                    "a `run` session started at {started_at} — an hour (UTC) with no prior \
                     session in this vault's history (baseline: 10+ sessions). Local \
                     sessions only; provider data has no time-of-day signal. Low \
                     confidence: schedules, travel, and CI legitimately shift hours."
                ),
                evidence: format!("session={session_id} started_at={started_at} hour_utc={hour}"),
                confidence: Confidence::Low,
                recommended_action: "confirm the session was yours (see `key history` / \
                                     activity)"
                    .into(),
                project_id: Some(project_id),
                credential_id: None,
                observed_at: observed.clone(),
            });
        }
    }

    // --- Destination drift.
    {
        let mut stmt = conn.prepare(
            "SELECT cd.credential_id, d.name, cd.secret_name, cd.drift
             FROM credential_destinations cd JOIN destinations d ON d.id = cd.destination_id
             WHERE cd.drift IN ('drifted', 'missing')",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (cred, dest, secret_name, drift) = row?;
            let label = label_of(&cred);
            out.push(NewAlert {
                kind: AlertKind::DestinationDrift,
                severity: if drift == "drifted" {
                    Severity::High
                } else {
                    Severity::Medium
                },
                dedup_key: format!("destination_drift:{cred}:{dest}:{secret_name}"),
                title: format!("destination drift: {label} @ {dest}"),
                detail: format!(
                    "'{secret_name}' at destination '{dest}' is {drift} relative to the \
                     vault value (verified by the last drift check)."
                ),
                evidence: format!("drift={drift} destination={dest} secret={secret_name}"),
                confidence: Confidence::High,
                recommended_action: "run `sync plan` to redeploy, or update the vault if the \
                                     destination is the intended truth"
                    .into(),
                project_id: None,
                credential_id: Some(cred),
                observed_at: observed.clone(),
            });
        }
    }

    // --- Rotations needing attention (manual action required).
    {
        let mut stmt = conn.prepare(
            "SELECT id, credential_id, state, last_error FROM rotations
             WHERE state = 'manual_required'",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (rotation_id, cred, state, last_error) = row?;
            let label = label_of(&cred);
            out.push(NewAlert {
                kind: AlertKind::RotationAttention,
                severity: Severity::Medium,
                dedup_key: format!("rotation_attention:{rotation_id}"),
                title: format!("rotation needs manual action: {label}"),
                detail: format!(
                    "rotation {rotation_id} is '{state}'{}. See `rotation show` for the \
                     exact steps.",
                    if last_error.is_empty() {
                        String::new()
                    } else {
                        format!(" ({last_error})")
                    }
                ),
                evidence: format!("rotation={rotation_id} state={state}"),
                confidence: Confidence::High,
                recommended_action: "perform the listed manual step, then `rotation \
                                     complete-manual`"
                    .into(),
                project_id: None,
                credential_id: Some(cred),
                observed_at: observed.clone(),
            });
        }
    }

    // --- Temporary access grants that expired in the last day.
    {
        let day_ago = days_ago(now, 1);
        let now_s = crate::clock::to_rfc3339(now);
        let mut stmt = conn.prepare(
            "SELECT id, project_id, label FROM access_grants
             WHERE revoked_at IS NULL AND expires_at >= ?1 AND expires_at <= ?2",
        )?;
        let rows = stmt.query_map(params![day_ago, now_s], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (grant_id, project_id, grant_label) = row?;
            out.push(NewAlert {
                kind: AlertKind::AccessGrantExpired,
                severity: Severity::Info,
                dedup_key: format!("access_grant_expired:{grant_id}"),
                title: format!(
                    "temporary access expired{}",
                    if grant_label.is_empty() {
                        String::new()
                    } else {
                        format!(": {grant_label}")
                    }
                ),
                detail: "the grant's window ended; new launches are refused. Reminder: local \
                         expiry bounds THIS machine only — the provider credential remains \
                         valid until revoked."
                    .into(),
                evidence: format!("grant={grant_id}"),
                confidence: Confidence::High,
                recommended_action: "create a new grant if still needed, or revoke the \
                                     provider key if the work is done"
                    .into(),
                project_id: Some(project_id),
                credential_id: None,
                observed_at: observed.clone(),
            });
        }
    }

    // --- Stale pricing for models with recent estimated usage. Estimates
    // keep being produced (labeled stale); this makes the staleness loud.
    {
        let month_ago = days_ago(now, 30);
        let mut stmt = conn.prepare(
            "SELECT DISTINCT provider, model FROM usage_snapshots
             WHERE model IS NOT NULL AND estimated_cost_micros IS NOT NULL
               AND window_start >= ?1",
        )?;
        let pairs = stmt
            .query_map(params![month_ago], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (provider, model) in pairs {
            let Some(rec) = crate::pricing::lookup_as_of(conn, &provider, &model, &observed)?
            else {
                continue;
            };
            if rec.stale {
                out.push(NewAlert {
                    kind: AlertKind::PricingStale,
                    severity: Severity::Low,
                    dedup_key: format!("pricing_stale:{provider}:{model}"),
                    title: format!("pricing data for {provider}/{model} may be stale"),
                    detail: format!(
                        "the price record used for this model's estimates was last verified \
                         {} (more than {} days ago). Estimates remain labeled and are NOT \
                         recomputed; verify the current price and refresh with `pricing \
                         propose {provider}` + `pricing import`, or set an override.",
                        rec.last_verified,
                        crate::pricing::STALE_AFTER_DAYS
                    ),
                    evidence: format!(
                        "record origin={} effective_from={} last_verified={} source={}",
                        rec.origin.as_str(),
                        rec.effective_from,
                        rec.last_verified,
                        rec.source
                    ),
                    confidence: Confidence::High,
                    recommended_action: "verify the provider's published price and import a \
                                         reviewed update or an override"
                        .into(),
                    project_id: None,
                    credential_id: None,
                    observed_at: observed.clone(),
                });
            }
        }
    }

    Ok(out)
}
