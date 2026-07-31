//! Verification: two deliberately separated proofs.
//!
//! 1. **Path proof (synthetic)** — the keyless probe: one credential-free
//!    GET through the gateway per route. A provider 401/403 proves
//!    DNS → gateway → TLS → provider. Extracted from the CLI's post-link
//!    probe so desktop, CLI, and diagnosis share one implementation.
//!    Proves Tethra's side; says nothing about the user's app.
//! 2. **Traffic proof (real)** — `traffic_observed` requires at least one
//!    recorded gateway observation for this setup's project at/after
//!    apply. [`check_traffic`] is a single poll the UI/CLI drives; the
//!    derivation itself lives in `state::refresh` so a stale row can
//!    never overclaim.

use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use api_tracker_core::Result;
use api_tracker_gateway::control;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

use crate::state::{self, ProviderFreshness, TrackingSetup, TrackingState};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// The provider answered 401/403 to a keyless request — the route
    /// works end to end.
    ProviderAnswered { status: String },
    /// The provider answered something else; the path still works.
    Forwarded { status: String },
    /// The gateway itself answered — the route did not forward.
    GatewayAnswered { status: String },
    /// Nothing is listening on the port.
    NoListener,
    /// Something is listening but did not verify as this vault's gateway.
    NotVerified { detail: String },
    /// Connection/read error.
    Unreachable { error: String },
}

impl ProbeOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(
            self,
            ProbeOutcome::ProviderAnswered { .. } | ProbeOutcome::Forwarded { .. }
        )
    }
}

/// One credential-free GET through the gateway (no Authorization header —
/// that is the "keyless" property). Response read is capped at 4 KiB.
pub fn probe_route(data_dir: &Path, port: u16, base_url: &str) -> ProbeOutcome {
    match control::verify_listener(data_dir, port) {
        control::ListenerIdentity::Verified { .. } => {}
        control::ListenerIdentity::NoListener => return ProbeOutcome::NoListener,
        other => {
            return ProbeOutcome::NotVerified {
                detail: format!("{other:?}"),
            }
        }
    }
    let probe_url = if base_url.ends_with("/v1") {
        format!("{base_url}/models")
    } else {
        format!("{base_url}/v1/models")
    };
    let prefix = format!("http://127.0.0.1:{port}");
    let path_only = probe_url.strip_prefix(&prefix).unwrap_or("/").to_string();

    let attempt = || -> std::io::Result<String> {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        let req = format!(
            "GET {path_only} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes())?;
        let mut response = String::new();
        Read::take(&mut stream, 4096).read_to_string(&mut response)?;
        Ok(response)
    };
    match attempt() {
        Ok(response) => {
            let status = response
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            let from_gateway = response.contains("tethra-gateway:");
            match (status.as_str(), from_gateway) {
                ("401" | "403", _) => ProbeOutcome::ProviderAnswered { status },
                (s, false) if !s.is_empty() => ProbeOutcome::Forwarded { status },
                (_, true) => ProbeOutcome::GatewayAnswered { status },
                _ => ProbeOutcome::Unreachable {
                    error: "no readable answer".to_string(),
                },
            }
        }
        Err(e) => ProbeOutcome::Unreachable {
            error: e.to_string(),
        },
    }
}

/// What one observed exchange looked like, for the verified banner.
#[derive(Debug, Clone, Serialize)]
pub struct ObservedExchange {
    pub provider_id: Option<String>,
    pub host: String,
    pub at: String,
    pub latency_ms: Option<i64>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WatchStatus {
    /// All configured providers observed at/after apply.
    Observed {
        exchange: Option<ObservedExchange>,
        freshness: Vec<ProviderFreshness>,
    },
    /// Some providers observed, others not yet — expected until the app
    /// calls them; Tethra keeps watching.
    PartiallyObserved {
        exchange: Option<ObservedExchange>,
        freshness: Vec<ProviderFreshness>,
    },
    /// Nothing yet.
    Waiting,
    /// The setup is not in a watchable state (not applied, undone, …).
    NotWatchable { state: TrackingState },
}

/// The most recent qualifying observation for this setup, for surfaces that
/// want to quote one.
///
/// Split out of [`check_traffic`] so a caller that has already resolved
/// present-tense health through [`crate::health::resolve`] can quote an
/// exchange **without** going back through the cached-state ladder. That
/// ladder is liveness-blind by construction, and `NEW-01` was a caller that
/// used it to decide whether to make a success claim rather than only to
/// decorate one.
pub fn latest_observed_exchange(
    conn: &Connection,
    setup: &TrackingSetup,
) -> Result<Option<ObservedExchange>> {
    latest_exchange(conn, setup)
}

/// One poll: refresh the derived state and report it. The caller decides
/// cadence (2 s UI, 5 s CLI) and timeout handling.
///
/// # This is not a health check
///
/// The returned [`WatchStatus`] switches on the **cached** `state` column
/// after a [`state::GatewayLiveness::Unknown`] refresh. `Observed` therefore
/// means "a qualifying exchange was recorded at some point in this
/// verification session", not "tracking is working now": it survives the
/// gateway being stopped, the route being removed and the link being
/// deleted. A surface that makes a present-tense claim — a headline, an exit
/// code — must use [`crate::health::resolve`] instead (`NEW-01`/`VER-02`).
pub fn check_traffic(conn: &Connection, setup: &mut TrackingSetup) -> Result<WatchStatus> {
    let freshness = state::refresh(conn, setup)?;
    match setup.state {
        TrackingState::TrafficObserved => Ok(WatchStatus::Observed {
            exchange: latest_exchange(conn, setup)?,
            freshness,
        }),
        TrackingState::PartiallyObserved => Ok(WatchStatus::PartiallyObserved {
            exchange: latest_exchange(conn, setup)?,
            freshness,
        }),
        TrackingState::AwaitingRestart
        | TrackingState::AwaitingFirstRequest
        | TrackingState::NeedsAttention => Ok(WatchStatus::Waiting),
        other => Ok(WatchStatus::NotWatchable { state: other }),
    }
}

fn latest_exchange(conn: &Connection, setup: &TrackingSetup) -> Result<Option<ObservedExchange>> {
    let Some(applied_at) = &setup.applied_at else {
        return Ok(None);
    };
    // Admissibility matches `state::refresh_with` exactly (RA-005): the same
    // insertion-ordered watermark and the same clock-skew bound. If this
    // query were looser, the screen would quote an exchange the derivation
    // refused to count — "verified" next to an event that proves nothing.
    let future_after = api_tracker_core::clock::rfc3339_minus_seconds(
        &api_tracker_core::clock::now_rfc3339(),
        -state::MAX_CLOCK_SKEW_SECS,
    );
    let row = conn
        .query_row(
            "SELECT host, at, latency_ms, id FROM runtime_request_events
             WHERE project_id = ?1 AND observation_source = 'gateway'
               AND rowid > ?3 AND at >= ?2 AND at <= ?4
             ORDER BY at DESC LIMIT 1",
            rusqlite::params![
                setup.project_id,
                applied_at,
                setup.applied_event_rowid,
                future_after
            ],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((host, at, latency_ms, event_id)) = row else {
        return Ok(None);
    };
    let (provider_id, model) = conn
        .query_row(
            "SELECT provider_id, model FROM gateway_usage_events WHERE event_id = ?1",
            [&event_id],
            |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()?
        .unwrap_or((None, None));
    let provider_id = provider_id.or_else(|| {
        api_tracker_core::runtime::inventory::provider_for_host(&host).map(String::from)
    });
    Ok(Some(ObservedExchange {
        provider_id,
        host,
        at,
        latency_ms,
        model,
    }))
}
