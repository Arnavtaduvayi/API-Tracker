//! Assembling a running gateway: listener, writer, control channel.
//!
//! This is the composition root for `tethra gateway run` (foreground) and,
//! later, for the installed service. It owns the one place where the pieces
//! know about each other, and it implements the control plane's view of a
//! live gateway.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::secret::SecretBytes;

use crate::control::{ControlServer, ControlTarget, Status};
use crate::forward::Gateway;
use crate::routes::{RouteState, RouteTarget};
use crate::server::{self, Listener};
use crate::writer::{Writer, WriterState};

/// How often the running gateway re-checks the route table for changes.
pub const ROUTE_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// How often background loops check whether a stop was requested. Small
/// enough that `tethra gateway stop` feels immediate.
const SHUTDOWN_CHECK_INTERVAL: Duration = Duration::from_millis(50);

/// How many consecutive "vault.db is gone" samples must agree before the
/// service self-unloads. The exit is terminal under both service managers, so
/// a transient stat failure must not be able to trigger it.
const VANISHED_VAULT_CONFIRMATIONS: u8 = 3;

/// The hard cap on keep-while-locked matching-key retention (ADR 0020): even
/// with the consented toggle ON, a locked vault keeps the resident key for at
/// most this long (one working day away from the keyboard), then attribution
/// pauses honestly until the user pushes the key again.
pub const MATCH_WHILE_LOCKED_TTL_CAP_MINUTES: u32 = 480;

/// What a vault-lock event does to the resident matching key (ADR 0020).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockDisposition {
    /// Drop the key now: the vault session that authorized it has ended and
    /// the user has not consented to locked-vault matching.
    RevokeNow,
    /// The consented, default-OFF `match_while_locked` toggle is ON: retain
    /// the key for at most this many minutes, then revoke.
    Retain { ttl_minutes: u32 },
}

/// Clamp a caller-supplied retention request to the consented bound.
/// `None` and `0` both mean "the locking session had no auto-lock duration"
/// (auto-lock disabled, or a caller that could not read the setting) — the
/// cap applies. Pure, so the clamp itself is unit-testable.
pub fn effective_retention_minutes(requested: Option<u32>) -> u32 {
    match requested {
        None | Some(0) => MATCH_WHILE_LOCKED_TTL_CAP_MINUTES,
        Some(v) => v.min(MATCH_WHILE_LOCKED_TTL_CAP_MINUTES),
    }
}

/// Decide what a vault-lock event does, from the plaintext config alone.
///
/// The policy lives HERE, in the service, not in the frontends: every lock
/// path (desktop manual/auto-lock/backup-restore, CLI lock, app exit) sends
/// the same `VaultLocked` signal and this one function decides. Reading the
/// toggle needs no vault — `gateway_config` is a plaintext table.
///
/// Fails toward revocation: a database that cannot be opened, a missing or
/// malformed config row, or a toggle that reads OFF all yield `RevokeNow`.
/// Retention never happens by accident (SI-9).
pub fn lock_disposition(db_path: &Path, requested_ttl_minutes: Option<u32>) -> LockDisposition {
    let keep = api_tracker_core::db::open_at_current_version(db_path)
        .ok()
        .and_then(|conn| crate::store::load_config(&conn).ok())
        .is_some_and(|c| c.match_while_locked);
    if keep {
        LockDisposition::Retain {
            ttl_minutes: effective_retention_minutes(requested_ttl_minutes),
        }
    } else {
        LockDisposition::RevokeNow
    }
}

/// The bounded keep-while-locked retention window for the resident matching
/// key (ADR 0020). Armed by a `VaultLocked` signal when the consented toggle
/// is ON; disarmed by unlock, re-push, revoke, or stop; enforced by the
/// service's poller thread.
///
/// The deadline is tracked on BOTH the monotonic and the wall clock and
/// expires when EITHER passes: monotonic clocks can pause across system
/// sleep (which would silently stretch the window), and a wall clock can be
/// set backwards (which would too). Taking the earlier of the two fails
/// toward revocation.
#[derive(Default)]
pub struct KeyRetention {
    deadline: Mutex<Option<(Instant, SystemTime)>>,
    expired: AtomicBool,
}

impl KeyRetention {
    /// Arm the window, never extending one that is already running: repeated
    /// lock events (auto-lock poll + explicit lock + app exit) must only ever
    /// tighten the deadline.
    pub fn arm_no_later_than(&self, ttl: Duration) {
        let candidate = (Instant::now() + ttl, SystemTime::now() + ttl);
        let mut guard = self.deadline.lock().expect("key retention lock");
        match &*guard {
            Some((existing, _)) if *existing <= candidate.0 => {}
            _ => *guard = Some(candidate),
        }
    }

    /// Cancel the window (unlock, fresh push, revoke, stop).
    pub fn disarm(&self) {
        *self.deadline.lock().expect("key retention lock") = None;
    }

    /// Whether a window is armed, and how long remains (for status honesty).
    pub fn remaining_secs(&self) -> Option<u64> {
        let guard = self.deadline.lock().expect("key retention lock");
        guard
            .as_ref()
            .map(|(instant, _)| instant.saturating_duration_since(Instant::now()).as_secs())
    }

    /// If the window has expired (on either clock), disarm it, record the
    /// expiry for status, and return true — the caller must then drop the
    /// key and matcher. Called from the poller loop.
    pub fn expire_if_due(&self) -> bool {
        let mut guard = self.deadline.lock().expect("key retention lock");
        let due = match &*guard {
            None => false,
            Some((instant, wall)) => Instant::now() >= *instant || SystemTime::now() >= *wall,
        };
        if due {
            *guard = None;
            self.expired.store(true, Ordering::Relaxed);
        }
        due
    }

    /// The last resident key was dropped by window expiry (cleared on the
    /// next successful push).
    pub fn expired(&self) -> bool {
        self.expired.load(Ordering::Relaxed)
    }

    pub fn clear_expired(&self) {
        self.expired.store(false, Ordering::Relaxed);
    }

    /// Test hook: arm an already-expired window so expiry enforcement can be
    /// exercised without sleeping through a real TTL.
    #[doc(hidden)]
    pub fn arm_already_expired_for_test(&self) {
        *self.deadline.lock().expect("key retention lock") =
            Some((Instant::now(), SystemTime::now()));
    }
}

/// A fully assembled, running gateway.
pub struct Service {
    gateway: Gateway,
    routes: Arc<RouteState>,
    writer_state: Arc<WriterState>,
    writer: Option<Writer>,
    control: Option<ControlServer>,
    data_dir: PathBuf,
    started: Instant,
    control_error: Option<String>,
    retention: Arc<KeyRetention>,
    listener_handle: Option<std::thread::JoinHandle<()>>,
    poller_handle: Option<std::thread::JoinHandle<()>>,
}

/// The control plane's handle on a live gateway. Cloneable, cheap, and
/// deliberately narrow: these are the ONLY things the control channel can do.
#[derive(Clone)]
pub struct ServiceControl {
    gateway: Gateway,
    routes: Arc<RouteState>,
    writer_state: Arc<WriterState>,
    writer_sink: Arc<crate::writer::WriterSink>,
    db_path: PathBuf,
    started: Instant,
    retention: Arc<KeyRetention>,
}

impl ControlTarget for ServiceControl {
    fn status(&self) -> Status {
        let table = self.routes.table();
        let unavailable = table
            .iter_routes()
            .filter(|r| matches!(r.target, RouteTarget::Unforwardable(_)))
            .count();
        Status {
            version: env!("CARGO_PKG_VERSION").to_string(),
            port: self.gateway.port,
            uptime_secs: self.started.elapsed().as_secs(),
            routes: table.len(),
            routes_unavailable: unavailable,
            connections_in_flight: self.gateway.connections.load(Ordering::Relaxed),
            queue_depth: self.writer_sink.queue_depth(),
            dropped_events: self.writer_state.dropped(),
            written_events: self.writer_state.written(),
            persist_failures: self.writer_state.persist_failures.load(Ordering::Relaxed),
            routes_degraded: self.routes.degraded(),
            recording_degraded: self.writer_state.is_degraded(),
            recording_paused: self.gateway.recording_paused.load(Ordering::Relaxed),
            matching_key_present: self.gateway.has_matching_key(),
            route_key_present: self.routes.has_mac_key(),
            last_observation_at: self.writer_state.last_written_at(),
            last_error: self.writer_state.last_error(),
            routes_disabled: table.disabled,
            routes_skipped: table.skipped.clone(),
            pid: std::process::id(),
            matching_key_deadline_secs: self.retention.remaining_secs(),
            matching_key_expired: self.retention.expired(),
        }
    }

    fn push_key(&self, key: SecretBytes) -> Result<()> {
        // Installing the key does two things, in this order: the forwarding
        // path can now digest presented credentials, and the writer gets the
        // SCOPED matcher table (linked, non-password-locked projects only —
        // never vault-wide). BOTH must succeed: with the key installed but
        // the matcher missing, every exchange would be recorded
        // `unavailable_no_key` while status claimed attribution was on.
        let matcher = crate::writer::load_matcher(&self.db_path)?;
        if !self.writer_sink.set_matcher(Some(matcher)) {
            return Err(CoreError::Busy);
        }
        self.gateway.set_matching_key(Some(key));
        // A fresh push is a fresh authorization: any pending keep-while-
        // locked deadline belongs to the previous session (ADR 0020).
        self.retention.disarm();
        self.retention.clear_expired();
        Ok(())
    }

    fn revoke_key(&self) {
        // The forwarding half is dropped FIRST and unconditionally: once the
        // key is gone no new digests are produced, so a matcher that could
        // not be cleared is never consulted again.
        self.gateway.set_matching_key(None);
        self.writer_sink.set_matcher(None);
        self.retention.disarm();
    }

    fn set_route_key(&self, key: Option<SecretBytes>) {
        // Reloads the snapshot, so a custom route becomes forwardable the
        // moment the key lands rather than at the next 5-second poll.
        self.routes.set_mac_key(key);
    }

    fn vault_locked(&self, ttl_minutes: Option<u32>) {
        // SI-9 / ADR 0020: the default answer to a lock is revocation, and
        // an unreadable policy fails toward revocation too. Only the
        // consented, default-OFF toggle earns bounded retention.
        if !self.gateway.has_matching_key() {
            self.retention.disarm();
            return;
        }
        match lock_disposition(&self.db_path, ttl_minutes) {
            LockDisposition::RevokeNow => self.revoke_key(),
            LockDisposition::Retain { ttl_minutes } => self
                .retention
                .arm_no_later_than(Duration::from_secs(u64::from(ttl_minutes) * 60)),
        }
    }

    fn vault_unlocked(&self) {
        self.retention.disarm();
    }

    fn reload_routes(&self) {
        self.routes.reload();
    }

    fn set_recording_paused(&self, paused: bool) {
        self.gateway
            .recording_paused
            .store(paused, Ordering::Relaxed);
    }

    fn shutdown(&self) {
        self.gateway.shutdown.store(true, Ordering::Relaxed);
    }
}

impl Service {
    /// Start every piece. `port` may be 0 for an ephemeral port (tests and
    /// first-run); the actual port is reported by [`Service::port`].
    ///
    /// A bind failure is returned as an error rather than exiting the
    /// process: the installed service must report "degraded: port held" and
    /// retry, because a fast-exiting process is a crash loop under launchd
    /// and a permanent failure under systemd's start-rate limit (ADR 0019
    /// D8).
    pub fn start(data_dir: &Path, port: u16) -> Result<Self> {
        let db_path = data_dir.join("vault.db");
        if crate::control::instance_is_live(data_dir) {
            return Err(CoreError::InvalidInput(
                "another Tethra gateway is already running for this data directory".into(),
            ));
        }
        let listener = Listener::bind(port)?;
        let bound_port = listener.port();

        // Claim single-instance ownership of the control socket BEFORE
        // writing any shared file. `instance_is_live` above is a connect
        // probe, and two concurrent first-run starts both pass it (neither
        // has bound the socket yet) — the second then CLOBBERED gateway.nonce
        // and gateway.pid, leaving the healthy first instance unreachable to
        // every nonce-authenticated call, reported as a port squatter by
        // `verify_listener`, and its runtime files deleted when the second
        // instance exited. The socket bind is the only real mutual exclusion,
        // so it has to come first.
        let claim = crate::control::claim_instance(data_dir)?;

        let nonce = crate::control::write_nonce(data_dir)?;
        // The boot id is its OWN random value, never the control nonce: it is
        // written into the plaintext `observation_sessions.command` column and
        // shown by `tethra observe sessions`, and the nonce is a live control
        // capability that must not be persisted or displayed anywhere.
        let boot_id = crate::control::random_boot_id();
        let writer = Writer::start(&db_path, boot_id);
        let writer_state = writer.state();
        let sink = writer.sink();

        let routes = Arc::new(RouteState::new(&db_path));
        let gateway = Gateway::new(routes.clone(), sink.clone(), bound_port);
        // The listener answers identity challenges derived from this boot's
        // nonce (D11), so status/link/doctor can distinguish this gateway
        // from a port squatter without the nonce crossing the TCP socket.
        gateway.set_probe_key(Some(crate::control::probe_key_from_nonce(&nonce)));
        crate::control::write_pid_file(data_dir)?;

        let retention = Arc::new(KeyRetention::default());
        let control_target = ServiceControl {
            gateway: gateway.clone(),
            routes: routes.clone(),
            writer_state: writer_state.clone(),
            writer_sink: sink.clone(),
            db_path: db_path.clone(),
            started: Instant::now(),
            retention: retention.clone(),
        };
        // A control channel that cannot start is a REAL degradation (no
        // status, no attribution, no graceful stop), so the reason is kept
        // and surfaced rather than swallowed.
        let (control, control_error) = match ControlServer::start_claimed(
            claim,
            data_dir,
            nonce.to_string(),
            Arc::new(control_target) as Arc<dyn ControlTarget>,
        ) {
            Ok(server) => (Some(server), None),
            Err(e) => (None, Some(e.to_string())),
        };

        let serve_gw = gateway.clone();
        let taps = server::usage_tap_factory();
        let listener_handle = std::thread::Builder::new()
            .name("tethra-gateway-accept".into())
            .spawn(move || server::serve_with_taps(serve_gw, listener, taps))
            .ok();

        // Route changes are picked up by polling SQLite's data_version, which
        // is cheap and needs no vault. The same loop enforces the bounded
        // keep-while-locked retention window (ADR 0020): every slice it
        // checks the deadline, so an expiry drops the key within
        // SHUTDOWN_CHECK_INTERVAL of falling due.
        let poll_routes = routes.clone();
        let poll_gw = gateway.clone();
        let poll_sink = sink.clone();
        let poll_retention = retention.clone();
        let poller_handle = std::thread::Builder::new()
            .name("tethra-gateway-routes".into())
            .spawn(move || {
                let enforce = || {
                    if poll_retention.expire_if_due() {
                        // Same order as an explicit revoke: key first, so no
                        // new digests are produced, then the matcher.
                        poll_gw.set_matching_key(None);
                        poll_sink.set_matcher(None);
                    }
                };
                while !poll_gw.shutdown.load(Ordering::Relaxed) {
                    poll_routes.reload_if_changed();
                    // Sleep in small slices so a stop is observed promptly:
                    // sleeping the whole poll interval would make shutdown
                    // wait up to ROUTE_POLL_INTERVAL for no reason.
                    let mut slept = Duration::ZERO;
                    while slept < ROUTE_POLL_INTERVAL && !poll_gw.shutdown.load(Ordering::Relaxed) {
                        enforce();
                        std::thread::sleep(SHUTDOWN_CHECK_INTERVAL);
                        slept += SHUTDOWN_CHECK_INTERVAL;
                    }
                }
            })
            .ok();

        Ok(Self {
            gateway,
            routes,
            writer_state,
            writer: Some(writer),
            control,
            data_dir: data_dir.to_path_buf(),
            started: Instant::now(),
            control_error,
            retention,
            listener_handle,
            poller_handle,
        })
    }

    /// The keep-while-locked retention state (status honesty + tests).
    pub fn key_retention(&self) -> &Arc<KeyRetention> {
        &self.retention
    }

    pub fn port(&self) -> u16 {
        self.gateway.port
    }

    pub fn gateway(&self) -> &Gateway {
        &self.gateway
    }

    pub fn routes(&self) -> &Arc<RouteState> {
        &self.routes
    }

    pub fn writer_state(&self) -> &Arc<WriterState> {
        &self.writer_state
    }

    /// Why the control channel is unavailable, when it is. `None` means it
    /// is running. Callers MUST surface this: without it there is no status,
    /// no attribution, and no graceful stop.
    pub fn control_unavailable(&self) -> Option<&str> {
        self.control_error.as_deref()
    }

    /// How long this gateway has been up.
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Whether a shutdown has been requested (by signal or control channel).
    pub fn is_stopping(&self) -> bool {
        self.gateway.shutdown.load(Ordering::Relaxed)
    }

    /// Block until a stop is requested, then shut down cleanly. This is what
    /// `tethra gateway run` calls.
    pub fn run_until_stopped(mut self) {
        while !self.is_stopping() {
            std::thread::sleep(Duration::from_millis(100));
        }
        self.stop();
    }

    /// Like [`Service::run_until_stopped`], but also returns when
    /// `extra_stop` fires (checked ~1/s). Reports WHY the loop ended so the
    /// service wrapper can exit with the right semantics.
    pub fn run_until_stopped_or(mut self, mut extra_stop: impl FnMut() -> bool) -> ServiceExit {
        let mut ticks: u32 = 0;
        loop {
            if self.is_stopping() {
                self.stop();
                return ServiceExit::StopRequested;
            }
            ticks = ticks.wrapping_add(1);
            if ticks % 10 == 0 && extra_stop() {
                self.stop();
                return ServiceExit::ExternalCondition;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Stop everything in the order that loses the least: stop accepting,
    /// let in-flight exchanges finish, drain the writer, then remove the
    /// control artifacts.
    pub fn stop(&mut self) {
        self.gateway.shutdown.store(true, Ordering::Relaxed);
        // Clear the matching key promptly on a GRACEFUL stop: it must not
        // outlive the process's usefulness. (This is not a signal handler —
        // SIGTERM/SIGKILL/crash skip this path entirely; see THREAT_MODEL
        // GW-6 for the honest statement of that limitation.)
        self.gateway.set_matching_key(None);
        self.retention.disarm();
        if let Some(h) = self.listener_handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.poller_handle.take() {
            let _ = h.join();
        }
        if let Some(mut w) = self.writer.take() {
            w.stop();
        }
        if let Some(mut c) = self.control.take() {
            c.stop();
        }
        // Only the instance that OWNED the control channel removes the
        // shared runtime files. A process whose control server never started
        // (Windows, or a socket claim that failed) must not delete the owner's
        // nonce and pid out from under it.
        if self.control_error.is_none() {
            crate::control::remove_pid_file(&self.data_dir);
            let _ = std::fs::remove_file(self.data_dir.join(crate::control::NONCE_NAME));
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if self.writer.is_some() || self.listener_handle.is_some() {
            self.stop();
        }
    }
}

/// Why a service-mode run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceExit {
    /// A control-channel shutdown (or signal-equivalent) was requested.
    StopRequested,
    /// The external condition fired (service mode: the data directory or
    /// vault database disappeared — the install was removed underneath us).
    ExternalCondition,
}

/// The `--service` wrapper around [`Service::start`] (ADR 0019 D8).
///
/// Two behaviors distinguish service mode from a foreground `serve`:
///
/// 1. **A bind failure never exits.** Under launchd `KeepAlive` a
///    fast-exiting process is a crash loop, and under systemd it trips the
///    start-rate limiter into a permanent failure — so a held port retries
///    here, in-process, with capped backoff, logging "degraded: port held"
///    through `log` each round.
/// 2. **A vanished install exits CLEANLY.** When the data directory or its
///    `vault.db` disappears (uninstalled underneath the service), the
///    service exits 0: `KeepAlive={Crashed:true}` and `Restart=on-failure`
///    both treat a clean exit as terminal, so nothing respawns against a
///    deleted vault.
///
/// `log` receives every lifecycle event line (no secrets ever); the caller
/// decides where it goes (stdout under launchd redirection, plus the
/// service log file).
pub fn run_as_service(data_dir: &Path, port: u16, mut log: impl FnMut(&str)) -> ServiceExit {
    let mut backoff = Duration::from_secs(1);
    loop {
        if !data_dir.join("vault.db").exists() {
            log("data directory or vault.db is gone; exiting cleanly (self-unload)");
            return ServiceExit::ExternalCondition;
        }
        match Service::start(data_dir, port) {
            Ok(service) => {
                let bound = service.port();
                log(&format!("gateway listening on 127.0.0.1:{bound}"));
                if let Some(why) = service.control_unavailable() {
                    log(&format!("control channel unavailable: {why}"));
                }
                let dir = data_dir.to_path_buf();
                // The vanished-vault self-exit is TERMINAL: launchd's
                // KeepAlive={Crashed:true} and systemd's Restart=on-failure
                // both treat a clean exit as final, so a single unlucky
                // sample permanently unloads the service until the user
                // reinstalls. `Path::exists()` is false for any stat error —
                // and `backup::restore` genuinely renames vault.db aside for
                // a real window — so require the condition to hold across
                // consecutive samples (~1s apart) before honoring it.
                let mut misses = 0u8;
                let exit = service.run_until_stopped_or(move || {
                    if dir.join("vault.db").exists() {
                        misses = 0;
                        false
                    } else {
                        misses = misses.saturating_add(1);
                        misses >= VANISHED_VAULT_CONFIRMATIONS
                    }
                });
                match exit {
                    ServiceExit::StopRequested => {
                        log("stop requested; exiting cleanly");
                        return ServiceExit::StopRequested;
                    }
                    ServiceExit::ExternalCondition => {
                        log("vault.db disappeared; exiting cleanly (self-unload)");
                        return ServiceExit::ExternalCondition;
                    }
                }
            }
            Err(e) => {
                // Most likely the port is held (or another instance is
                // live). Degrade visibly and retry — never exit (D8).
                log(&format!(
                    "degraded: could not start ({e}); retrying in {}s",
                    backoff.as_secs()
                ));
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}
