//! Assembling a running gateway: listener, writer, control channel.
//!
//! This is the composition root for `tethra gateway run` (foreground) and,
//! later, for the installed service. It owns the one place where the pieces
//! know about each other, and it implements the control plane's view of a
//! live gateway.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
            last_observation_at: self.writer_state.last_written_at(),
            last_error: self.writer_state.last_error(),
        }
    }

    fn push_key(&self, key: SecretBytes) -> Result<()> {
        // Installing the key does two things, in this order: the forwarding
        // path can now digest presented credentials, and the writer gets the
        // SCOPED matcher table (linked, non-password-locked projects only —
        // never vault-wide). BOTH must succeed: with the key installed but
        // the matcher missing, every exchange would be recorded
        // `unavailable_vault_locked` while status claimed attribution was on.
        let matcher = crate::writer::load_matcher(&self.db_path)?;
        if !self.writer_sink.set_matcher(Some(matcher)) {
            return Err(CoreError::Busy);
        }
        self.gateway.set_matching_key(Some(key));
        Ok(())
    }

    fn revoke_key(&self) {
        // The forwarding half is dropped FIRST and unconditionally: once the
        // key is gone no new digests are produced, so a matcher that could
        // not be cleared is never consulted again.
        self.gateway.set_matching_key(None);
        self.writer_sink.set_matcher(None);
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
        crate::control::write_pid_file(data_dir)?;

        let control_target = ServiceControl {
            gateway: gateway.clone(),
            routes: routes.clone(),
            writer_state: writer_state.clone(),
            writer_sink: sink.clone(),
            db_path: db_path.clone(),
            started: Instant::now(),
        };
        // A control channel that cannot start is a REAL degradation (no
        // status, no attribution, no graceful stop), so the reason is kept
        // and surfaced rather than swallowed.
        let (control, control_error) = match ControlServer::start(
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
        // is cheap and needs no vault.
        let poll_routes = routes.clone();
        let poll_gw = gateway.clone();
        let poller_handle = std::thread::Builder::new()
            .name("tethra-gateway-routes".into())
            .spawn(move || {
                while !poll_gw.shutdown.load(Ordering::Relaxed) {
                    poll_routes.reload_if_changed();
                    // Sleep in small slices so a stop is observed promptly:
                    // sleeping the whole poll interval would make shutdown
                    // wait up to ROUTE_POLL_INTERVAL for no reason.
                    let mut slept = Duration::ZERO;
                    while slept < ROUTE_POLL_INTERVAL && !poll_gw.shutdown.load(Ordering::Relaxed) {
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
            listener_handle,
            poller_handle,
        })
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

    /// Stop everything in the order that loses the least: stop accepting,
    /// let in-flight exchanges finish, drain the writer, then remove the
    /// control artifacts.
    pub fn stop(&mut self) {
        self.gateway.shutdown.store(true, Ordering::Relaxed);
        // Clear the matching key promptly: it must not outlive the process's
        // usefulness (SIGTERM handler equivalent).
        self.gateway.set_matching_key(None);
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
        crate::control::remove_pid_file(&self.data_dir);
        let _ = std::fs::remove_file(self.data_dir.join(crate::control::NONCE_NAME));
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if self.writer.is_some() || self.listener_handle.is_some() {
            self.stop();
        }
    }
}
