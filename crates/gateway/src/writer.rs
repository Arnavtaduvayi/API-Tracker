//! The dedicated observation writer (ADR 0019 D7).
//!
//! **The forwarding path never waits on persistence.** The sink hands an
//! `ExchangeRecord` to a bounded channel with `try_send`; a full queue DROPS
//! and COUNTS rather than applying backpressure. This deliberately inverts
//! `observe`'s blocking sink, because "forwarding continues when persistence
//! fails" is an immutable requirement and outranks "capture every event"
//! (SI-12). Everything that can be slow — opening the database, resolving a
//! fingerprint match, pricing, roll-up, retention — happens on this thread.
//!
//! **A locked vault changes nothing about forwarding.** The gateway tables
//! are plaintext operational metadata, so the writer keeps persisting while
//! the vault is locked; only credential ATTRIBUTION degrades, and it degrades
//! to its own honest state rather than to a false `unmatched`.
//!
//! **Nothing secret is ever queued.** `ExchangeRecord` structurally cannot
//! hold a body, header value, cookie, query, or credential; the only
//! credential-derived thing that crosses the channel is a keyed digest.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::runtime::model::{
    HttpMethod, ObservationMode, ObservationSource, ObservedRequest,
};
use api_tracker_core::runtime::{aggregate, retention, store as rstore};
use api_tracker_core::{clock, db, pricing};
use rusqlite::Connection;

use crate::attribution::{self, Attribution, Matcher, METHOD_OBSERVED_FINGERPRINT};
use crate::record::{counters, AttributionInput, ExchangeRecord, ObservationSink};
use crate::store;

/// Bounded queue depth. Sized so a burst is absorbed without letting a stalled
/// database grow memory without bound.
pub const QUEUE_CAPACITY: usize = 1024;
/// How often the writer drives roll-up and retention when otherwise idle.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(300);
/// How long a graceful shutdown waits for the queue to drain.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Max records written under one database connection.
pub const BATCH_MAX: usize = 256;

/// What the writer is told about the world, updated by the control plane.
#[derive(Default)]
pub struct WriterState {
    /// Events accepted onto the queue.
    pub queued: AtomicU64,
    /// Events dropped because the queue was full. Surfaced in status — a
    /// coverage gap is reported, never hidden.
    pub dropped: AtomicU64,
    /// Counter bumps dropped for the same reason. Counted separately so a
    /// "counters look low" question has an answer instead of a shrug.
    pub dropped_counters: AtomicU64,
    /// Events successfully persisted.
    pub written: AtomicU64,
    /// Events the writer could not persist (database busy/missing/schema
    /// drift). Also a coverage gap.
    pub persist_failures: AtomicU64,
    /// Whether persistence is currently degraded.
    pub degraded: AtomicBool,
    /// The most recent event timestamp actually persisted.
    pub last_written_at: Mutex<Option<String>>,
    /// The last persistence error, as a code (never wire-derived text).
    pub last_error: Mutex<Option<String>>,
}

impl WriterState {
    pub fn queue_depth(&self, live: usize) -> usize {
        live
    }
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
    pub fn dropped_counters(&self) -> u64 {
        self.dropped_counters.load(Ordering::Relaxed)
    }
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }
    pub fn last_written_at(&self) -> Option<String> {
        self.last_written_at.lock().ok().and_then(|g| g.clone())
    }
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|g| g.clone())
    }
}

enum Message {
    Record(Box<ExchangeRecord>),
    Counter {
        route: String,
        counter: String,
    },
    /// Install or clear the scoped matcher table (control channel).
    Matcher(Option<Matcher>),
    Flush(mpsc::Sender<()>),
}

/// The sink installed on the forwarding path. Every method is non-blocking.
pub struct WriterSink {
    tx: mpsc::SyncSender<Message>,
    state: Arc<WriterState>,
    in_flight: Arc<AtomicU64>,
}

impl WriterSink {
    pub fn state(&self) -> Arc<WriterState> {
        self.state.clone()
    }

    /// Approximate live queue depth (enqueued minus completed).
    pub fn queue_depth(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed) as usize
    }

    /// Install the scoped matcher table. Sent through the SAME channel as
    /// records so it can never race a record already queued.
    pub fn set_matcher(&self, matcher: Option<Matcher>) {
        let _ = self.tx.try_send(Message::Matcher(matcher));
    }

    /// Block until everything queued so far has been processed. Used by the
    /// control plane and by tests; never called from the forwarding path.
    pub fn flush(&self, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        // A flush is NOT on the forwarding path, so unlike `record` it may
        // wait for a queue slot; a full queue must not make a drain
        // impossible.
        let deadline = Instant::now() + timeout;
        let mut message = Message::Flush(tx);
        loop {
            match self.tx.try_send(message) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Full(m)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    message = m;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => return false,
            }
        }
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok()
    }
}

impl ObservationSink for WriterSink {
    fn record(&self, record: ExchangeRecord) {
        // try_send, never send: a full queue must not add a microsecond of
        // latency to a forwarded request (SI-12).
        match self.tx.try_send(Message::Record(Box::new(record))) {
            Ok(()) => {
                self.state.queued.fetch_add(1, Ordering::Relaxed);
                self.in_flight.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => {
                // Honest coverage gap: counted, surfaced, never silent.
                self.state.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn count(&self, route_prefix: &str, counter: &str) {
        // Also try_send: a counter bump must never be able to slow a
        // forwarded request either. A dropped bump is itself counted, so an
        // under-reported counter is explainable rather than mysterious.
        if self
            .tx
            .try_send(Message::Counter {
                route: route_prefix.to_string(),
                counter: counter.to_string(),
            })
            .is_err()
        {
            self.state.dropped_counters.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A running writer thread.
pub struct Writer {
    sink: Arc<WriterSink>,
    state: Arc<WriterState>,
    handle: Option<std::thread::JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
}

impl Writer {
    /// Start the writer against a vault database path. The database is NOT
    /// opened here: the writer opens short-lived, schema-checked connections
    /// per flush so it never holds vault.db open across the desktop app's
    /// checkpoint-on-lock.
    pub fn start(db_path: &Path, boot_id: String) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Message>(QUEUE_CAPACITY);
        let state = Arc::new(WriterState::default());
        let in_flight = Arc::new(AtomicU64::new(0));
        let sink = Arc::new(WriterSink {
            tx: tx.clone(),
            state: state.clone(),
            in_flight: in_flight.clone(),
        });
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = WriterThread {
            db_path: db_path.to_path_buf(),
            boot_id,
            state: state.clone(),
            in_flight: in_flight.clone(),
            matcher: None,
            sessions: Default::default(),
            batch_min: None,
            batch_max: None,
            stopping: stopping.clone(),
        };
        let handle = std::thread::Builder::new()
            .name("tethra-gateway-writer".into())
            .spawn(move || worker.run(rx))
            .ok();
        drop(tx);
        Self {
            sink,
            state,
            handle,
            stopping,
        }
    }

    pub fn sink(&self) -> Arc<WriterSink> {
        self.sink.clone()
    }

    pub fn state(&self) -> Arc<WriterState> {
        self.state.clone()
    }

    /// Stop the writer, draining what is already queued.
    ///
    /// The stop signal is an atomic flag, NOT a queued message: a full queue
    /// must never be able to prevent shutdown (an earlier version sent Stop
    /// with `try_send` and deadlocked exactly there). The writer observes the
    /// flag on every wake, finishes the batch in hand, and exits.
    pub fn stop(&mut self) -> bool {
        let drained = self.sink.flush(DRAIN_TIMEOUT);
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        drained
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.stop();
        }
    }
}

#[derive(Default)]
struct SessionCache {
    /// One session per (boot × linked project).
    by_project: std::collections::HashMap<String, String>,
}

struct WriterThread {
    db_path: PathBuf,
    boot_id: String,
    state: Arc<WriterState>,
    in_flight: Arc<AtomicU64>,
    matcher: Option<Matcher>,
    sessions: SessionCache,
    /// The timestamp range of the current batch, for the roll-up re-roll.
    batch_min: Option<String>,
    batch_max: Option<String>,
    stopping: Arc<AtomicBool>,
}

impl WriterThread {
    fn run(mut self, rx: mpsc::Receiver<Message>) {
        let mut next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
        // Close sessions left running by a previous boot that died.
        if let Ok(conn) = self.open() {
            let _ = rstore::sweep_orphaned_sessions(&conn);
        }
        loop {
            if self.stopping.load(Ordering::Relaxed) {
                break;
            }
            // Wait for work, then DRAIN what is already queued into one
            // batch. The connection is opened per BATCH, not per record, so
            // the writer never holds vault.db open across the desktop's
            // checkpoint-on-lock and a burst costs one open, not N.
            let first = match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(m) => Some(m),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let mut batch: Vec<Message> = Vec::new();
            if let Some(m) = first {
                batch.push(m);
                while batch.len() < BATCH_MAX {
                    match rx.try_recv() {
                        Ok(m) => batch.push(m),
                        Err(_) => break,
                    }
                }
            }
            let stop_requested = self.process_batch(batch);
            if stop_requested {
                break;
            }
            if Instant::now() >= next_maintenance {
                self.maintenance();
                next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
            }
        }
        // Drain anything still queued so a clean stop loses nothing it
        // already accepted.
        let mut tail: Vec<Message> = Vec::new();
        while let Ok(m) = rx.try_recv() {
            tail.push(m);
            if tail.len() >= BATCH_MAX * 4 {
                break;
            }
        }
        self.process_batch(tail);
        self.maintenance();
        self.finish_sessions();
    }

    /// Process one batch under a single database connection. Returns whether
    /// a stop was requested.
    fn process_batch(&mut self, batch: Vec<Message>) -> bool {
        if batch.is_empty() {
            return false;
        }
        let mut replies: Vec<mpsc::Sender<()>> = Vec::new();
        let mut records: Vec<Box<ExchangeRecord>> = Vec::new();
        let mut counters_batch: Vec<(String, String)> = Vec::new();
        for msg in batch {
            match msg {
                Message::Matcher(m) => self.matcher = m,
                Message::Flush(reply) => replies.push(reply),
                Message::Counter { route, counter } => counters_batch.push((route, counter)),
                Message::Record(r) => records.push(r),
            }
        }
        let record_count = records.len() as u64;
        match self.open() {
            Ok(conn) => {
                let day = clock::now_rfc3339();
                for (route, counter) in counters_batch {
                    let _ = store::bump_counter(&conn, &route, store::day_of(&day), &counter, 1);
                }
                for record in records {
                    self.persist_one(&conn, *record);
                }
            }
            Err(e) => {
                // Persistence is down: count the loss honestly, never block.
                for _ in 0..record_count {
                    self.note_failure(&e);
                }
            }
        }
        if record_count > 0 {
            self.in_flight.fetch_sub(record_count, Ordering::Relaxed);
        }
        if !replies.is_empty() {
            self.maintenance();
            for reply in replies {
                let _ = reply.send(());
            }
        }
        // Stopping is signalled by the atomic flag, never by a queued
        // message: a full queue must not be able to prevent shutdown.
        self.stopping.load(Ordering::Relaxed)
    }

    /// A short-lived, schema-checked connection. `db::open` performs NO schema
    /// check, and a background process that outlives an app upgrade would
    /// otherwise INSERT into a schema it does not understand
    /// (KNOWN_CONFLICTS C15).
    fn open(&self) -> Result<Connection> {
        match db::open_at_current_version(&self.db_path) {
            Ok(conn) => {
                self.state.degraded.store(false, Ordering::Relaxed);
                Ok(conn)
            }
            Err(e) => {
                self.state.degraded.store(true, Ordering::Relaxed);
                if let Ok(mut slot) = self.state.last_error.lock() {
                    *slot = Some(e.code().to_string());
                }
                Err(e)
            }
        }
    }

    fn note_failure(&self, e: &CoreError) {
        self.state.persist_failures.fetch_add(1, Ordering::Relaxed);
        self.state.degraded.store(true, Ordering::Relaxed);
        if let Ok(mut slot) = self.state.last_error.lock() {
            // A CODE, never wire-derived text.
            *slot = Some(e.code().to_string());
        }
    }

    fn persist_one(&mut self, conn: &Connection, record: ExchangeRecord) {
        if let Err(e) = self.persist_with(conn, &record) {
            self.note_failure(&e);
            return;
        }
        self.state.written.fetch_add(1, Ordering::Relaxed);
        self.state.degraded.store(false, Ordering::Relaxed);
        if let Ok(mut slot) = self.state.last_written_at.lock() {
            *slot = Some(record.at.clone());
        }
        let at = record.at.clone();
        self.batch_min = Some(match self.batch_min.take() {
            Some(cur) if cur <= at => cur,
            _ => at.clone(),
        });
        self.batch_max = Some(match self.batch_max.take() {
            Some(cur) if cur >= at => cur,
            _ => at,
        });
    }

    fn persist_with(&mut self, conn: &Connection, record: &ExchangeRecord) -> Result<()> {
        // Unlinked traffic is counted at route level and given NO invented
        // project attribution.
        let Some(project_id) = record.project_id.clone() else {
            return store::bump_counter(
                conn,
                &record.route_prefix,
                store::day_of(&record.at),
                counters::UNLINKED_REQUESTS,
                1,
            );
        };
        // A project row can disappear between link time and now.
        let project_exists: bool = conn
            .query_row(
                "SELECT 1 FROM projects WHERE id = ?1",
                rusqlite::params![project_id],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !project_exists {
            return Ok(());
        }

        let session_id = self.session_for(conn, &project_id)?;
        let (service_id, previously_known) = rstore::upsert_service(
            conn,
            &record.host,
            Some(&record.provider_id),
            false,
            &record.at,
        )?;
        let (endpoint_id, _) = rstore::upsert_endpoint(
            conn,
            &service_id,
            record.method,
            &record.path_template,
            record.template_confidence,
            &record.at,
        )?;

        let observed = ObservedRequest {
            host: record.host.clone(),
            port: record.port,
            method: record.method,
            path_template: record.path_template.clone(),
            template_confidence: record.template_confidence,
            status_code: record.status_code,
            req_content_kind: record.req_content_kind,
            resp_content_kind: record.resp_content_kind,
            had_authorization: record.had_authorization,
            latency_ms: record.latency_ms,
            request_bytes: record.request_bytes,
            response_bytes: record.response_bytes,
            protocol: api_tracker_core::runtime::model::Protocol::Http11,
            observation_source: ObservationSource::Gateway,
            transport_error: record.transport_error,
        };
        let event_id = rstore::insert_request_event(
            conn,
            &session_id,
            &project_id,
            &service_id,
            Some(&endpoint_id),
            &record.at,
            &observed,
            previously_known,
        )?;

        // An exchange that did not complete is honestly a partial-coverage
        // session: the numbers describe part of an exchange, not all of it.
        if !record.completion.is_complete_coverage() {
            let _ = rstore::set_partial_coverage(conn, &session_id, true);
            store::bump_counter(
                conn,
                &record.route_prefix,
                store::day_of(&record.at),
                record.completion.as_str(),
                1,
            )?;
        }

        self.attribute(conn, &event_id, record)?;
        self.write_usage(conn, &event_id, &project_id, record)?;
        Ok(())
    }

    /// Resolve the credential digest against the scoped matcher table. This
    /// is the ONLY place the lookup runs, and it runs HERE — off the
    /// forwarding path — so no request timing depends on whether a
    /// credential matched.
    fn attribute(&self, conn: &Connection, event_id: &str, record: &ExchangeRecord) -> Result<()> {
        let attribution = match (&record.digest, &self.matcher) {
            (Some(digest), Some(matcher)) => matcher.resolve(digest),
            (Some(_), None) => Attribution::UnavailableVaultLocked,
            (None, _) => match record.attribution_input {
                AttributionInput::NoCredentialPresent => Attribution::NoCredentialPresent,
                AttributionInput::UnsupportedForm => Attribution::UnsupportedForm,
                AttributionInput::UnavailableVaultLocked | AttributionInput::Digested => {
                    Attribution::UnavailableVaultLocked
                }
            },
        };
        // The attribution STATE is always recorded, including its counter, so
        // "how much traffic could not be attributed and why" is answerable.
        store::bump_counter(
            conn,
            &record.route_prefix,
            store::day_of(&record.at),
            &format!("attribution_{}", attribution.as_str()),
            1,
        )?;
        if attribution.credential_id().is_none() {
            return Ok(());
        }
        rstore::set_event_attribution(
            conn,
            event_id,
            attribution.credential_id(),
            attribution.confidence(),
            METHOD_OBSERVED_FINGERPRINT,
            match &attribution {
                Attribution::MatchedOldVersion { version, .. } => Some(*version),
                _ => None,
            },
            match &attribution {
                Attribution::Matched { .. } => Some(true),
                Attribution::MatchedOldVersion { .. } => Some(false),
                _ => None,
            },
        )?;
        // Only a single confirmed match bumps last_used_at: it means "some
        // process on this machine presented this exact value".
        if attribution.bumps_last_used() {
            if let Some(id) = attribution.credential_id() {
                let _ = conn.execute(
                    "UPDATE credentials SET last_used_at = ?2 WHERE id = ?1",
                    rusqlite::params![id, record.at],
                );
            }
        }
        Ok(())
    }

    /// Gateway usage goes to the gateway tables ONLY — never
    /// `usage_snapshots`, whose `totals()` sums every source and would
    /// double-count against provider admin sync (KNOWN_CONFLICTS C8).
    fn write_usage(
        &self,
        conn: &Connection,
        event_id: &str,
        project_id: &str,
        record: &ExchangeRecord,
    ) -> Result<()> {
        let Some(usage) = &record.usage else {
            return Ok(());
        };
        let cost = usage
            .model
            .as_deref()
            .and_then(|model| {
                pricing::estimate_token_cost_as_of(
                    conn,
                    &record.provider_id,
                    model,
                    &record.at,
                    usage.input_tokens.unwrap_or(0) as i64,
                    usage.output_tokens.unwrap_or(0) as i64,
                )
                .ok()
                .flatten()
            })
            .map(|c| c.micros);

        conn.execute(
            "INSERT INTO gateway_usage_events
                (id, event_id, at, route_prefix, provider_id, project_id, model,
                 input_tokens, output_tokens, total_tokens, cached_input_tokens,
                 usage_available, usage_state, estimated_cost_micros, was_streamed)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                event_id,
                record.at,
                record.route_prefix,
                record.provider_id,
                project_id,
                usage.model,
                usage.input_tokens.map(|v| v as i64),
                usage.output_tokens.map(|v| v as i64),
                usage.total_tokens.map(|v| v as i64),
                usage.cached_input_tokens.map(|v| v as i64),
                usage.available() as i64,
                usage.state.as_str(),
                cost,
                usage.was_streamed as i64,
            ],
        )?;

        conn.execute(
            "INSERT INTO gateway_usage_daily
                (day, provider_id, project_id, model, request_count, usage_event_count,
                 input_tokens, output_tokens, cached_input_tokens, estimated_cost_micros,
                 updated_at)
             VALUES (?1,?2,?3,?4,1,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(day, provider_id, project_id, model) DO UPDATE SET
                request_count = request_count + 1,
                usage_event_count = usage_event_count + excluded.usage_event_count,
                input_tokens = input_tokens + excluded.input_tokens,
                output_tokens = output_tokens + excluded.output_tokens,
                cached_input_tokens = cached_input_tokens + excluded.cached_input_tokens,
                estimated_cost_micros = estimated_cost_micros + excluded.estimated_cost_micros,
                updated_at = excluded.updated_at",
            rusqlite::params![
                store::day_of(&record.at),
                record.provider_id,
                project_id,
                usage.model.clone().unwrap_or_default(),
                usage.available() as i64,
                usage.input_tokens.unwrap_or(0) as i64,
                usage.output_tokens.unwrap_or(0) as i64,
                usage.cached_input_tokens.unwrap_or(0) as i64,
                cost.unwrap_or(0),
                clock::now_rfc3339(),
            ],
        )?;
        Ok(())
    }

    fn session_for(&mut self, conn: &Connection, project_id: &str) -> Result<String> {
        if let Some(id) = self.sessions.by_project.get(project_id) {
            // Confirm it still exists (a delete-all could have removed it).
            let alive: bool = conn
                .query_row(
                    "SELECT 1 FROM observation_sessions WHERE id = ?1 AND status = 'running'",
                    rusqlite::params![id],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            if alive {
                return Ok(id.clone());
            }
            self.sessions.by_project.remove(project_id);
        }
        let id = rstore::insert_session(
            conn,
            &rstore::NewSession {
                project_id,
                mode: ObservationMode::Metadata,
                source: "gateway",
                command: &format!("tethra-gateway (boot {})", self.boot_id),
                credential_names: &[],
            },
        )?;
        // Record the pid so a crashed boot's session is closed honestly by
        // `sweep_orphaned_sessions` rather than left "running" forever.
        let _ = rstore::set_session_runtime(
            conn,
            &id,
            Some(std::process::id()),
            None,
            None,
            Some("gateway"),
            None,
        );
        self.sessions
            .by_project
            .insert(project_id.to_string(), id.clone());
        Ok(id)
    }

    /// Roll-up and retention, driven by the gateway's own timer because a
    /// monitored run may never happen. Needs a database connection only —
    /// no vault key.
    fn maintenance(&mut self) {
        let Ok(conn) = self.open() else {
            return;
        };
        let now = clock::now_rfc3339();
        let _ = aggregate::roll_up(&conn, &now);
        // After a flush, re-roll the batch's own hour range: the roll-up
        // watermark only ever moves forward, so a late-flushed event would
        // otherwise be permanently excluded from its bucket
        // (KNOWN_CONFLICTS C17).
        if let (Some(min), Some(max)) = (self.batch_min.take(), self.batch_max.take()) {
            let _ = aggregate::reroll_hours(&conn, &min, &max);
        }
        let _ = retention::sweep(&conn);
        let _ = self.sweep_gateway_tables(&conn);
    }

    /// Retention for the gateway's own tables: `retention::sweep` covers only
    /// `runtime_request_events` and `runtime_metric_buckets`, so these would
    /// otherwise grow without bound (KNOWN_CONFLICTS C16).
    fn sweep_gateway_tables(&self, conn: &Connection) -> Result<()> {
        let config = store::load_config(conn)?;
        let event_days = config
            .usage_event_retention_days
            .unwrap_or(store::DEFAULT_USAGE_EVENT_RETENTION_DAYS);
        let daily_days = config
            .usage_daily_retention_days
            .unwrap_or(store::DEFAULT_USAGE_DAILY_RETENTION_DAYS);
        let now = clock::now();
        let event_cutoff = clock::to_rfc3339(now - Duration::from_secs(event_days as u64 * 86_400));
        let daily_cutoff = clock::to_rfc3339(now - Duration::from_secs(daily_days as u64 * 86_400));
        conn.execute(
            "DELETE FROM gateway_usage_events WHERE at < ?1",
            rusqlite::params![event_cutoff],
        )?;
        conn.execute(
            "DELETE FROM gateway_usage_daily WHERE day < ?1",
            rusqlite::params![store::day_of(&daily_cutoff)],
        )?;
        conn.execute(
            "DELETE FROM gateway_route_counters WHERE day < ?1",
            rusqlite::params![store::day_of(&daily_cutoff)],
        )?;
        Ok(())
    }

    /// Close this boot's sessions on a clean stop. A session is never left
    /// silently "running" and never silently marked completed after a crash
    /// (that is `sweep_orphaned_sessions`'s job, with its own honest reason).
    fn finish_sessions(&mut self) {
        let Ok(conn) = self.open() else {
            return;
        };
        for id in self.sessions.by_project.values() {
            let _ = rstore::finish_session(&conn, id, None);
        }
        self.sessions.by_project.clear();
    }
}

/// Build the scoped matcher from a database, for the control plane to push.
pub fn load_matcher(db_path: &Path) -> Result<Matcher> {
    let conn = db::open_at_current_version(db_path)?;
    Ok(Matcher::new(attribution::load_matcher_table(&conn)?))
}

/// A helper for surfacing the method the funnel used, so status output can
/// state its evidence class honestly.
pub fn observation_source_label() -> &'static str {
    ObservationSource::Gateway.as_str()
}

/// The `HttpMethod` the gateway records for an unparsed verb.
pub fn method_other() -> HttpMethod {
    HttpMethod::Other
}
