//! The ordered install primitive: everything that has to happen in one
//! sequence for an installed gateway to be reachable at the port the rest
//! of the product believes in.
//!
//! ## Why this exists (NEW-02)
//!
//! The installed service is started with argv `gateway serve --service
//! --data-dir <dir>` and NO port: it resolves its port at boot by reading
//! `gateway_config.port`. The CLI's install verb started the service and
//! only then committed the port, so a service that booted inside that
//! window read a `NULL` port — instantly and without an error, because the
//! database is WAL and a reader takes the last committed snapshot rather
//! than blocking — and bound an unrelated ephemeral port. Nothing compared
//! the bound port with the persisted one afterwards, so `status` and
//! `doctor` reported healthy while every linked `.env` pointed at a dead
//! port. It is the root cause of the one unexplained packaged-link CI
//! failure.
//!
//! Two other install paths (desktop onboarding, tracking apply) happened to
//! order it correctly by hand and said so in comments. That is exactly the
//! problem this module removes: the ordering was a convention every caller
//! had to remember, not a property of the operation. `install_gateway` is
//! correct on its own, whatever order its caller does things in.
//!
//! ## The order, and what each step owes the next
//!
//! 1. **Validate the whole plan** — before anything can need undoing.
//! 2. **Reserve/select the port** — and HOLD the socket, so nothing can take
//!    the port between choosing it and writing it down.
//! 3. **Persist the configuration** — one `BEGIN IMMEDIATE` transaction that
//!    touches only `port`. This is the commit the service's boot-time read
//!    depends on; nothing after it may run before it.
//! 4. **Persist the service definition** — atomically (temp + rename, see
//!    [`super::atomic_write_definition`]), inside [`super::Lifecycle::install`].
//! 5. **Register and start** — also inside the engine, which already rolls
//!    its own artifacts back.
//! 6. **Verify the service reads the intended configuration** — an identity
//!    probe on the INTENDED port, plus the running process's own belief
//!    about which port it bound. Failure is fatal, so an exit code stops
//!    lying about it.
//! 7. **Roll back coherently** — every artifact this call created, and
//!    nothing it did not. `config.port` is deliberately never rolled back.

use std::path::Path;
use std::time::Duration;

use api_tracker_core::error::{CoreError, Result};
use rusqlite::Connection;

use super::{bin_dir, logs_dir, DefinitionState, InstallReport, Lifecycle};
use crate::control::{self, ListenerIdentity};
use crate::store::{self, GatewayConfig};

/// A port this installer has decided on, and — when it chose the port
/// itself — the socket that keeps anyone else from taking it.
///
/// The CLI used to bind `127.0.0.1:0`, read the port, and drop the listener
/// immediately, leaving a TOCTOU window in which any process (including a
/// second concurrent `tethra gateway install`) could claim the port about
/// to be written into the database and from there into `.env` files.
/// Holding the socket until the moment the service is started shrinks that
/// window to the microseconds between [`PortReservation::release`] and the
/// service's own `bind`, and the identity probe in step 6 closes even that:
/// if something else did take it, the install fails loudly instead of
/// leaving a lie in the database.
pub struct PortReservation {
    port: u16,
    holder: Option<std::net::TcpListener>,
}

impl PortReservation {
    /// A port that is already persisted (or supplied by a fake). Nothing is
    /// bound: our own running gateway may legitimately hold it, and step 1
    /// has already proved the port is either ours or free.
    pub fn adopted(port: u16) -> Self {
        Self { port, holder: None }
    }

    /// Bind a free loopback port and hold it.
    pub fn fresh() -> Result<Self> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(CoreError::Io)?;
        let port = listener.local_addr().map_err(CoreError::Io)?.port();
        Ok(Self {
            port,
            holder: Some(listener),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Give the port up so the service can bind it. Called once, immediately
    /// before the start — never earlier (that is the TOCTOU window) and
    /// never later (the service would hit `EADDRINUSE` and spend a visible
    /// backoff round recovering from us).
    pub fn release(&mut self) {
        self.holder = None;
    }
}

/// The ordered milestones, emitted as they are reached.
///
/// This is a specification a test can assert against: the defect NEW-02
/// describes is precisely a pair of these arriving in the wrong order, and
/// asserting the sequence catches a regression that reorders any pair, not
/// only the two the audit happened to find.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallStage {
    /// Nothing has happened yet and nothing needs undoing.
    PlanValidated,
    PortSelected {
        port: u16,
        fresh: bool,
    },
    /// The load-bearing commit: from here on, a service booting for this
    /// data directory reads the right port.
    PortCommitted {
        port: u16,
    },
    /// Definition written, registered, and started (the engine's own D8
    /// order).
    ServiceStarted {
        port: u16,
    },
    /// The listener on the intended port proved it is this data directory's
    /// gateway.
    ListenerVerified {
        port: u16,
    },
    /// `enabled` + `service_version` + the audit row, one transaction.
    Enabled {
        port: u16,
    },
    /// Something this call created was undone. Rollback is reported, never
    /// silent.
    RolledBack {
        action: String,
    },
    Note(String),
}

/// Everything the installer needs from outside the database and the service
/// manager: sockets, the control channel, time, and progress reporting.
///
/// [`super::Lifecycle`] already carries an injectable `CommandRunner` and
/// `ServiceManager`, so this is the ONLY new seam, and it exists purely so
/// tests can run the whole ordered algorithm without binding a port,
/// sleeping, or going anywhere near a real launchd job.
pub trait InstallHost {
    fn reserve_port(&self) -> Result<PortReservation>;
    fn verify_listener(&self, data_dir: &Path, port: u16) -> ListenerIdentity;
    /// The running gateway's OWN belief about which port it bound. This is
    /// the assertion that catches NEW-02 directly: a listener probe on the
    /// intended port only proves that port is silent, while this says which
    /// port the process actually took.
    fn control_status(&self, data_dir: &Path) -> Option<control::Status>;
    fn sleep(&self, d: Duration);
    fn observe(&self, _stage: InstallStage) {}
}

/// The real host: real sockets, the real control channel, real time.
pub struct HostEnvironment {
    observer: Box<dyn Fn(&InstallStage) + Send + Sync>,
}

impl HostEnvironment {
    pub fn new(observer: impl Fn(&InstallStage) + Send + Sync + 'static) -> Self {
        Self {
            observer: Box::new(observer),
        }
    }

    pub fn quiet() -> Self {
        Self::new(|_| {})
    }
}

impl InstallHost for HostEnvironment {
    fn reserve_port(&self) -> Result<PortReservation> {
        PortReservation::fresh()
    }

    fn verify_listener(&self, data_dir: &Path, port: u16) -> ListenerIdentity {
        control::verify_listener(data_dir, port)
    }

    fn control_status(&self, data_dir: &Path) -> Option<control::Status> {
        if !control::instance_is_live(data_dir) {
            return None;
        }
        let nonce = control::read_nonce(data_dir).ok()?;
        match control::send(
            data_dir,
            &control::Request::Status {
                nonce: nonce.to_string(),
            },
        ) {
            Ok(control::Response::Status(s)) => Some(*s),
            _ => None,
        }
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    fn observe(&self, stage: InstallStage) {
        (self.observer)(&stage);
    }
}

/// One install, completely described. Nothing is read from ambient state,
/// so two frontends asking for the same install cannot disagree about what
/// they asked for.
pub struct InstallRequest<'a> {
    pub source_binary: &'a Path,
    /// Replace a definition that belongs to a different data directory.
    pub force: bool,
    /// The version recorded in `gateway_config.service_version`. Passed in
    /// rather than read from this crate's `CARGO_PKG_VERSION`, because the
    /// number that matters is the FRONTEND's — it is what `doctor` compares
    /// the installed binary against.
    pub service_version: &'a str,
    /// Identity-probe budget: `verify_attempts` × `probe_interval`.
    pub verify_attempts: u32,
    pub probe_interval: Duration,
}

impl<'a> InstallRequest<'a> {
    /// The product defaults: ten seconds of probing, in quarter seconds.
    pub fn new(source_binary: &'a Path, force: bool, service_version: &'a str) -> Self {
        Self {
            source_binary,
            force,
            service_version,
            verify_attempts: 40,
            probe_interval: Duration::from_millis(250),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallOutcome {
    pub report: InstallReport,
    /// The authoritative port — this call's choice, or the one a concurrent
    /// installer committed first.
    pub port: u16,
    /// Whether this call is what decided the port.
    pub port_was_new: bool,
}

/// Install (or re-install) the gateway service for `lc.data_dir`, in an
/// order that does not depend on the caller getting anything right.
pub fn install_gateway(
    lc: &Lifecycle,
    conn: &Connection,
    host: &dyn InstallHost,
    req: &InstallRequest<'_>,
) -> Result<InstallOutcome> {
    // --- 1. validate the complete plan (no side effects, nothing to undo) --
    let config = validate_plan(lc, conn, host, req)?;
    host.observe(InstallStage::PlanValidated);

    // --- 2. reserve/select the port -------------------------------------
    let (mut reservation, chose_fresh) = match config.port {
        Some(port) => (PortReservation::adopted(port), false),
        None => (host.reserve_port()?, true),
    };
    host.observe(InstallStage::PortSelected {
        port: reservation.port(),
        fresh: chose_fresh,
    });

    // --- 3. persist configuration atomically ----------------------------
    //
    // THE load-bearing commit. Everything after this line may be observed
    // by a service booting for this data directory; nothing before it may
    // be. `commit_port` serializes concurrent installers under
    // BEGIN IMMEDIATE and returns the winner's port, so two racing installs
    // converge on one port instead of writing two.
    let port = store::commit_port(conn, reservation.port())?;
    let port_was_new = chose_fresh && port == reservation.port();
    if port != reservation.port() {
        host.observe(InstallStage::Note(format!(
            "another installer committed port {port} first; using it rather than the \
             {} this run reserved",
            reservation.port()
        )));
    }
    host.observe(InstallStage::PortCommitted { port });

    // --- 4/5. definition, registration, start ---------------------------
    //
    // Released here and nowhere else: earlier reopens the TOCTOU window the
    // reservation exists to close, later makes our own service fight us for
    // the port.
    reservation.release();
    let report = match lc.install(req.source_binary, req.force) {
        Ok(report) => report,
        Err(e) => {
            let mut rollback = Vec::new();
            sweep_orphan_binary(lc, &mut rollback);
            for action in &rollback {
                host.observe(InstallStage::RolledBack {
                    action: action.clone(),
                });
            }
            return Err(annotate_rollback(e, &rollback));
        }
    };
    // Before the up-to-ten-second probe, not after it: the notes are where
    // the engine records that it took over a legacy agent or replaced
    // another data directory's definition, and a user who is about to stare
    // at a progress spinner should already know that happened. Emitting
    // them as stages also means they still reach the user when the
    // verification below fails.
    report_notes(host, &report);
    host.observe(InstallStage::ServiceStarted { port });

    // --- 6. verify the service reads the intended configuration ---------
    verify_service_port(lc, host, req, port)?;
    host.observe(InstallStage::ListenerVerified { port });

    // --- the completion commit ------------------------------------------
    //
    // `enabled`, the recorded version and the audit row go together, so a
    // crash can never leave an "enabled" gateway with no audit trail, nor
    // an audit row for an install that never came up. It is deliberately
    // AFTER verification: an install that could not be verified is not one
    // this product should describe as enabled.
    commit_enabled(conn, req.service_version, port, &report.definition)?;
    host.observe(InstallStage::Enabled { port });

    Ok(InstallOutcome {
        report,
        port,
        port_was_new,
    })
}

/// Re-align the installed service with this binary and data directory —
/// and, unlike the old repair path, make sure a port exists first.
///
/// `repair` is `install(force = false)` underneath, so it starts a service
/// that resolves its port from the database exactly like a fresh install
/// does. Repairing an installation whose `gateway_config.port` is still
/// `NULL` therefore produced the same `bind(0)` service NEW-02 describes,
/// from a path reached automatically by `tethra track` with no user
/// decision behind it. Repair does not enable anything and records no
/// install audit row; it only guarantees the port the service is about to
/// read.
pub fn repair_gateway(
    lc: &Lifecycle,
    conn: &Connection,
    host: &dyn InstallHost,
    req: &InstallRequest<'_>,
) -> Result<InstallOutcome> {
    let config = validate_plan(lc, conn, host, req)?;
    host.observe(InstallStage::PlanValidated);

    let (mut reservation, chose_fresh) = match config.port {
        Some(port) => (PortReservation::adopted(port), false),
        None => (host.reserve_port()?, true),
    };
    host.observe(InstallStage::PortSelected {
        port: reservation.port(),
        fresh: chose_fresh,
    });
    let port = store::commit_port(conn, reservation.port())?;
    let port_was_new = chose_fresh && port == reservation.port();
    host.observe(InstallStage::PortCommitted { port });

    reservation.release();
    let report = match lc.repair(req.source_binary) {
        Ok(report) => report,
        Err(e) => {
            let mut rollback = Vec::new();
            sweep_orphan_binary(lc, &mut rollback);
            for action in &rollback {
                host.observe(InstallStage::RolledBack {
                    action: action.clone(),
                });
            }
            return Err(annotate_rollback(e, &rollback));
        }
    };
    report_notes(host, &report);
    host.observe(InstallStage::ServiceStarted { port });

    verify_service_port(lc, host, req, port)?;
    host.observe(InstallStage::ListenerVerified { port });

    // Only the recorded version, and NOT best-effort: a repair that cannot
    // write the version leaves `doctor` reporting a drift it has just
    // repaired, and the same swallowed-error habit is what hid NEW-02.
    let mut config = store::load_config(conn)?;
    config.service_version = Some(req.service_version.to_string());
    store::save_config(conn, &config)?;

    Ok(InstallOutcome {
        report,
        port,
        port_was_new,
    })
}

/// Step 1. Everything that can refuse an install refuses here, before a
/// single byte is written — including the checks the engine repeats later
/// as defence in depth.
fn validate_plan(
    lc: &Lifecycle,
    conn: &Connection,
    host: &dyn InstallHost,
    req: &InstallRequest<'_>,
) -> Result<GatewayConfig> {
    let force = req.force;
    if !lc.data_dir.is_dir() {
        return Err(CoreError::InvalidInput(format!(
            "the data directory {} does not exist; nothing can be installed against it",
            lc.data_dir.display()
        )));
    }
    // Named here rather than surfacing as a bare io error from the
    // byte-write halfway through the install.
    if !req.source_binary.is_file() {
        return Err(CoreError::InvalidInput(format!(
            "the helper binary to install from ({}) does not exist or is not a file",
            req.source_binary.display()
        )));
    }
    // The slot's ownership. The engine checks this too, but only after the
    // byte-write — and by then a failure has already left an orphan binary
    // and (before this module) a half-decided port.
    match lc.manager.read_definition_state()? {
        DefinitionState::Present(existing)
            if !super::same_data_dir(&existing.data_dir, &lc.data_dir) && !force =>
        {
            return Err(CoreError::InvalidInput(format!(
                "a Tethra gateway service is already installed for a different data \
                 directory ({}). Uninstall it first, or pass --force to replace it.",
                existing.data_dir.display()
            )));
        }
        DefinitionState::Unparseable if !force => {
            return Err(CoreError::InvalidInput(format!(
                "{} already exists but could not be parsed as a Tethra service \
                 definition. Tethra will not overwrite a definition it cannot prove is \
                 its own; inspect or remove the file, or pass --force.",
                lc.manager.definition_path().display()
            )));
        }
        _ => {}
    }

    // Writability of everything the install is about to create, checked now
    // so a failure costs nothing.
    std::fs::create_dir_all(bin_dir(&lc.data_dir)).map_err(CoreError::Io)?;
    std::fs::create_dir_all(logs_dir(&lc.data_dir)).map_err(CoreError::Io)?;

    let config = store::load_config(conn)?;
    // A persisted port that a STRANGER holds must stop the install here.
    // Today that only becomes a `doctor` finding after the fact, by which
    // point the service is registered, started, and losing its port race.
    if let Some(port) = config.port {
        match host.verify_listener(&lc.data_dir, port) {
            ListenerIdentity::NotOurs | ListenerIdentity::NoNonce => {
                return Err(CoreError::InvalidInput(format!(
                    "port {port} is the persisted gateway port for this data directory, \
                     but a process that cannot prove it is this vault's gateway is \
                     listening on it. Installing now would point every linked project at \
                     whatever owns that port. Free the port (or stop the other process) \
                     and try again."
                )));
            }
            ListenerIdentity::Verified { .. } | ListenerIdentity::NoListener => {}
        }
    }
    Ok(config)
}

/// Surface everything the engine recorded about what it had to do —
/// legacy-agent migrations, forced replacements, pruned helper binaries.
fn report_notes(host: &dyn InstallHost, report: &InstallReport) {
    for note in &report.notes {
        host.observe(InstallStage::Note(note.clone()));
    }
    for pruned in &report.pruned_binaries {
        host.observe(InstallStage::Note(format!(
            "removed older helper binary {pruned}"
        )));
    }
}

/// Step 6. Two independent assertions, because each catches a failure the
/// other cannot see.
fn verify_service_port(
    lc: &Lifecycle,
    host: &dyn InstallHost,
    req: &InstallRequest<'_>,
    port: u16,
) -> Result<()> {
    let mut verified = false;
    for _ in 0..req.verify_attempts {
        host.sleep(req.probe_interval);
        if matches!(
            host.verify_listener(&lc.data_dir, port),
            ListenerIdentity::Verified { .. }
        ) {
            verified = true;
            break;
        }
    }

    // The process's own belief about its port. A drifted gateway answers
    // the control channel perfectly well — that is exactly why `status` and
    // `doctor` called the failure healthy — so this is the only check that
    // sees it.
    let live = host.control_status(&lc.data_dir);
    if let Some(status) = &live {
        if status.port != port {
            return Err(CoreError::InvalidInput(format!(
                "the gateway started, but it is serving on port {} while this data \
                 directory's configuration says {port}. Every linked .env was written \
                 with 127.0.0.1:{port}, so those projects would get connection-refused. \
                 The persisted port is the authority: `tethra gateway restart` makes the \
                 service bind it again and the existing .env files become correct with \
                 no re-link.",
                status.port
            )));
        }
    }

    if !verified {
        // Deliberately NOT a teardown. The service, its definition and its
        // registration are left in place: the overwhelmingly likely cause
        // is a service that is still coming up, and destroying a working
        // install over a slow probe would be a worse failure than the one
        // being reported. What must not survive is the SILENCE — the old
        // path printed a note and returned `Ok(())`, so every
        // exit-code-only caller (the packaged CI harness among them)
        // recorded a success.
        return Err(CoreError::InvalidInput(format!(
            "the service was installed and started, but nothing answered this data \
             directory's identity probe on port {port} within {}s. The service \
             definition and registration were left in place so the state can be \
             inspected: run `tethra gateway doctor`, then `tethra gateway restart`.",
            (req.verify_attempts as u64 * req.probe_interval.as_millis() as u64) / 1000
        )));
    }
    Ok(())
}

/// The completion commit (`enabled` + version + audit), one transaction.
fn commit_enabled(conn: &Connection, version: &str, port: u16, definition: &str) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<()> {
        let mut config = store::load_config(conn)?;
        config.enabled = true;
        config.service_version = Some(version.to_string());
        store::save_config(conn, &config)?;
        api_tracker_core::audit::record(
            conn,
            "gateway_service_installed",
            None,
            None,
            &format!("port={port} definition={definition}"),
        )
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// The engine rolls back its definition and registration but leaves the
/// freshly byte-written helper behind. Harmless (the next successful
/// install prunes it) but it is an artifact of a failed operation, so it
/// goes — and only when no definition survived, i.e. nothing points at it.
fn sweep_orphan_binary(lc: &Lifecycle, rollback: &mut Vec<String>) {
    let definition_survived = !matches!(
        lc.manager.read_definition_state(),
        Ok(DefinitionState::Absent)
    );
    if definition_survived {
        return;
    }
    let binary = lc.installed_binary_path();
    if binary.exists() && std::fs::remove_file(&binary).is_ok() {
        rollback.push(format!(
            "removed the helper binary this failed install wrote ({})",
            binary.display()
        ));
    }
}

/// `config.port` is NOT in this list, and never will be: a persisted port
/// with no service is exactly the state `tracking::plan::ensure_port`
/// deliberately produces, `.env` files written by an earlier successful
/// link already carry it, and clearing it would turn a retryable install
/// into a re-link.
fn annotate_rollback(e: CoreError, rollback: &[String]) -> CoreError {
    if rollback.is_empty() {
        return e;
    }
    CoreError::InvalidInput(format!(
        "{e}\nrolled back: {}\nthe persisted gateway port was KEPT, so a retry reuses it \
         and any .env already written against it stays correct",
        rollback.join("; ")
    ))
}
