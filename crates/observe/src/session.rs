//! Monitored-run orchestration: the glue that turns an unlocked vault + a
//! child command into a fully observed session.
//!
//! Flow (metadata mode): ensure the CA (generate + vault-encrypt on first
//! use) → open a session row → start the loopback proxy → drain observed
//! metadata on a dedicated writer thread (its own DB connection) → prepare
//! scoped trust and launch the child with only child-scoped environment
//! changes → record process identity → wait → tear the proxy down, invalidate
//! the token, drop the CA key material → attribute, aggregate, prune, and
//! finish the session honestly.

use crate::ca::{self, CertAuthority};
use crate::policy::AllowList;
use crate::proxy::{ObservationSink, ProxyConfig, RunningProxy};
use crate::trust::{detect_runtime, RuntimeAssessment, ScopedTrust};
use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::runtime::model::{HttpMethod, ObservationMode, ObservedRequest, TrustLevel};
use api_tracker_core::runtime::{aggregate, attribution, inventory, retention, store};
use api_tracker_core::vault::UnlockedVault;
use api_tracker_core::{clock, inject};
use base64::Engine;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

enum Msg {
    Event(Box<ObservedRequest>),
    Compat {
        check: String,
        status: String,
        detail: String,
    },
    Partial,
}

/// Bound on the number of unwritten events queued to the writer thread. A
/// BOUNDED channel is essential: on loopback the request-completion rate of tiny
/// keep-alive requests far exceeds the writer's per-event SQLite throughput, so
/// an unbounded queue grows without bound and OOMs the host under a flood. A
/// full channel blocks the sending proxy worker — that backpressure throttles
/// the OBSERVED CHILD (acceptable), never a real network peer.
const WRITER_CHANNEL_CAP: usize = 4096;

/// A sink that forwards observed metadata to the writer thread. `SyncSender` is
/// itself `Sync`, so many proxy worker threads can `record` concurrently without
/// a `Mutex`, each blocking individually only when the bounded queue is full.
struct ChannelSink {
    tx: SyncSender<Msg>,
}

impl ObservationSink for ChannelSink {
    fn record(&self, o: ObservedRequest) {
        let _ = self.tx.send(Msg::Event(Box::new(o)));
    }
    fn note_compat(&self, check: &str, status: &str, detail: &str) {
        let _ = self.tx.send(Msg::Compat {
            check: check.into(),
            status: status.into(),
            detail: detail.into(),
        });
    }
    fn mark_partial(&self, _reason: &str) {
        let _ = self.tx.send(Msg::Partial);
    }
}

/// How often the interruptible wait loop re-checks for child exit and lock
/// signals. This is a POLL INTERVAL (bounds responsiveness), NOT a
/// synchronization primitive — correctness depends only on the deterministic
/// checks it performs (`try_wait`, session-file stat, elapsed deadline), never
/// on the sleep duration.
const LOCK_POLL: Duration = Duration::from_millis(250);

/// Bounded best-effort attempts to reap a signalled child on the interrupt path
/// (× LOCK_POLL ≈ 2 s), after which the OS reaps it when the launcher exits.
const CHILD_REAP_TRIES: usize = 8;

/// Why an active observed run is being torn down by the lock watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockSignal {
    /// The session file was deleted — `api-tracker lock` (manual lock).
    Manual,
    /// The auto-lock deadline / session-file expiry passed (auto-lock / idle).
    Auto,
}

impl LockSignal {
    /// The non-secret interruption reason persisted to the session row.
    pub fn reason(self) -> &'static str {
        match self {
            LockSignal::Manual => "vault_locked",
            LockSignal::Auto => "auto_lock",
        }
    }
}

/// Tells [`run_monitored`] when to interrupt an active observed run because the
/// vault has been (or should be) locked. It is evaluated IN the process that
/// owns the live proxy + CA key (the CLI `run` process) — there is no
/// cross-process signalling, so it is fully portable (no signals, no `/proc`).
#[derive(Debug, Clone, Default)]
pub struct LockPolicy {
    /// Session file to watch. Deleted → Manual lock; present but past its
    /// recorded expiry → Auto lock. `None` for an inline-password run (there is
    /// no shared session file to lock).
    pub session_file: Option<PathBuf>,
    /// Hard wall-clock cap from run start (the vault's auto-lock TTL). Elapsed →
    /// Auto lock. `None` when auto-lock is disabled or a session file is watched
    /// instead (the file's own expiry is authoritative there).
    pub max_run: Option<Duration>,
}

impl LockPolicy {
    /// Return a lock signal if the run should be torn down now, else `None`.
    /// Cheap and pure (one file stat + an elapsed comparison).
    fn lock_signal(&self, started: Instant) -> Option<LockSignal> {
        if let Some(max) = self.max_run {
            if started.elapsed() >= max {
                return Some(LockSignal::Auto);
            }
        }
        if let Some(path) = &self.session_file {
            match api_tracker_core::session::peek_state(path) {
                api_tracker_core::session::SessionFileState::Missing => {
                    return Some(LockSignal::Manual)
                }
                api_tracker_core::session::SessionFileState::Expired => {
                    return Some(LockSignal::Auto)
                }
                api_tracker_core::session::SessionFileState::Active => {}
            }
        }
        None
    }
}

/// Parameters for a monitored run.
pub struct RunParams {
    pub project_id: String,
    pub mode: ObservationMode,
    pub source: String,
    pub command_label: String,
    pub credential_names: Vec<String>,
    /// Injected credentials, for attribution + old-version detection.
    pub injected: Vec<attribution::InjectedCredential>,
    /// Explicit internal-destination allowlist for this run.
    pub allowlist: Vec<(String, u16)>,
    /// When to interrupt the run because the vault locked / auto-locked.
    pub lock: LockPolicy,
}

/// The result of a monitored run.
pub struct RunOutcome {
    pub session_id: String,
    pub proxy_port: u16,
    pub assessment: RuntimeAssessment,
    pub exit_code: Option<i32>,
    pub attributions: usize,
    /// `Some(reason)` when the run was interrupted (e.g. by a vault lock)
    /// instead of the child exiting on its own; `None` on a normal finish.
    pub interrupt_reason: Option<String>,
    /// On an interruption, the non-secret outcome of terminating the monitored
    /// child (e.g. "SIGTERM sent …", "already exited", "refused: …"); `None`
    /// on a normal finish. Never contains secrets.
    pub child_termination: Option<String>,
}

fn random_token() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(api_tracker_core::crypto::random_bytes(32))
}

/// Ensure the vault has a CA, generating + storing one on first use, and return
/// a loaded [`CertAuthority`] plus the CA certificate PEM (for scoped trust).
fn ensure_ca(vault: &UnlockedVault) -> Result<(Arc<CertAuthority>, String)> {
    // Treat a stored CA that will not decrypt the SAME as "no CA": the AAD binds
    // the certificate PEM, so a tampered ca_cert_pem (a laundering attempt) or a
    // legacy-format record fails to authenticate. Regenerating a fresh CA
    // discards the swapped certificate — it is never used or installed.
    let existing = vault.observe_ca_material().unwrap_or_default();
    let (pem, key, fp) = match existing {
        Some(x) => x,
        None => {
            let g = ca::generate_ca(vault.vault_id())?;
            vault.observe_ca_store(
                &g.cert_pem,
                &g.key_der,
                &g.fingerprint_sha256,
                &g.serial_hex,
                &g.not_after,
            )?;
            (g.cert_pem, g.key_der, g.fingerprint_sha256)
        }
    };
    let authority = Arc::new(CertAuthority::load(vault.vault_id(), &pem, &key, &fp)?);
    // `key` (SecretBytes) drops here, zeroized; the authority holds its own
    // reconstituted signing key for the session.
    Ok((authority, pem))
}

/// Run `command` under observation. `program` is the child's program name (for
/// runtime detection).
pub fn run_monitored(
    vault: &UnlockedVault,
    params: RunParams,
    mut command: Command,
    program: &str,
) -> Result<RunOutcome> {
    let data_dir = vault.paths().data_dir.clone();
    let db_path = vault.paths().db_path();

    // 0. Detect the runtime FIRST so the effective mode can account for it.
    let assessment = detect_runtime(program);
    // A runtime that honors env proxying but cannot verify our minted leaf (Go
    // on macOS/Windows, which ignores SSL_CERT_FILE) would FAIL every HTTPS
    // request under metadata interception. Downgrade it to connection-only
    // observation (opaque tunnels) so it keeps working and is recorded honestly
    // at the connection level — instead of the false "falls back automatically"
    // the docs promised while the code left the mode unchanged.
    let effective_mode = if params.mode == ObservationMode::Metadata
        && assessment.trust_level == TrustLevel::ConnectionOnlyFallback
    {
        ObservationMode::Connection
    } else {
        params.mode
    };

    // 1. Certificate authority (metadata mode only).
    let ca = if effective_mode == ObservationMode::Metadata {
        Some(ensure_ca(vault)?)
    } else {
        None
    };
    let ca_pem = ca.as_ref().map(|(_, pem)| pem.clone()).unwrap_or_default();

    // 2. Session row (records the mode that ACTUALLY runs).
    let session_id = vault.observe_open_session(
        &params.project_id,
        effective_mode,
        &params.source,
        &params.command_label,
        &params.credential_names,
    )?;

    // 3. Proxy + channel sink + writer thread.
    let token = random_token();
    let (tx, rx) = mpsc::sync_channel(WRITER_CHANNEL_CAP);
    let sink = Arc::new(ChannelSink { tx });
    let mut allow = AllowList::new();
    for (h, p) in &params.allowlist {
        allow.insert(h, *p);
    }
    let proxy = RunningProxy::start(ProxyConfig {
        mode: effective_mode,
        ca: ca.as_ref().map(|(a, _)| a.clone()),
        token: token.clone(),
        allowlist: allow,
        max_connections: 64,
        sink: sink.clone(),
        upstream_config: None,
    })?;
    let port = proxy.local_addr().port();

    let writer_db = db_path.clone();
    let writer_session = session_id.clone();
    let writer = std::thread::spawn(move || run_writer(&writer_db, &writer_session, rx));

    // Honesty: never show a green "full coverage" dashboard for a run whose
    // requests bypassed interception. If we downgraded, or the runtime does not
    // honor scoped CA trust at all (Java/.NET) while metadata was requested,
    // flag partial coverage with a machine-readable reason.
    if effective_mode != params.mode {
        sink.note_compat(
            "runtime_trust",
            "downgraded",
            &format!(
                "{} cannot verify the local CA leaf; downgraded to connection-only observation",
                assessment.runtime
            ),
        );
        sink.mark_partial("runtime_connection_only");
    } else if effective_mode == ObservationMode::Metadata
        && assessment.trust_level == TrustLevel::Unsupported
    {
        sink.note_compat(
            "runtime_trust",
            "unsupported",
            &format!(
                "{} does not honor scoped CA trust; its HTTPS requests may fail or bypass interception",
                assessment.runtime
            ),
        );
        sink.mark_partial("runtime_unsupported");
    }

    // 4. Scoped trust (child-only env) + record port/runtime. The proxy token
    //    is embedded in the proxy URL so the child sends Proxy-Authorization
    //    automatically; it never leaves this function or reaches any DTO.
    let infix = &session_id[..8.min(session_id.len())];
    let trust = match ScopedTrust::prepare(&data_dir, port, &token, &ca_pem, effective_mode, infix)
    {
        Ok(t) => t,
        Err(e) => {
            proxy.shutdown();
            drop(sink);
            let _ = writer.join();
            store::interrupt_session(vault.connection(), &session_id, "trust_setup_failed")?;
            return Err(e);
        }
    };
    trust.apply(&mut command);
    let _ = store::set_session_runtime(
        vault.connection(),
        &session_id,
        None,
        None,
        Some(port),
        Some(&assessment.runtime),
        Some(assessment.trust_level),
    );

    // 5. Launch the child (with the injected credentials the caller already set
    //    on `command`, plus our scoped trust). Record identity.
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            proxy.shutdown();
            drop(sink);
            let _ = writer.join();
            store::interrupt_session(vault.connection(), &session_id, "child_spawn_failed")?;
            return Err(CoreError::InvalidInput(format!(
                "failed to launch '{program}': {e}"
            )));
        }
    };
    let pid = child.id();
    let identity = match inject::probe_process_identity(i64::from(pid)) {
        inject::IdentityProbe::Found(s) => Some(s),
        _ => None,
    };
    let _ = store::set_session_runtime(
        vault.connection(),
        &session_id,
        Some(pid),
        identity.as_deref(),
        None,
        None,
        None,
    );

    // 6. Wait for the child, but REMAIN INTERRUPTIBLE. A blocking `child.wait()`
    //    would let the proxy keep terminating TLS and hold the CA signing key in
    //    memory for the child's whole lifetime, regardless of a manual `lock` or
    //    the vault's auto-lock timeout. Instead we poll: on each tick check
    //    whether the child exited, and whether the lock policy says to tear the
    //    run down now. The poll interval bounds responsiveness only; the checks
    //    are deterministic.
    let started = Instant::now();
    let mut exit_code: Option<i32> = None;
    let mut interrupt: Option<LockSignal> = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => {}
            // Cannot wait on the child (should not happen): stop watching rather
            // than spin, and tear down as if it is gone.
            Err(_) => break,
        }
        if let Some(signal) = params.lock.lock_signal(started) {
            interrupt = Some(signal);
            break;
        }
        std::thread::sleep(LOCK_POLL);
    }

    // 7. Tear down. proxy.shutdown() FIRST: it force-closes every in-flight
    //    client socket, stops the listener, releases the ephemeral port, and
    //    kills the per-session token. NO further traffic is decrypted after this
    //    returns — this is the security-critical step for a vault lock.
    proxy.shutdown();

    // On a lock interruption the child is still running; terminate it
    // (fail-closed) via the verified-identity path — it refuses on PID reuse /
    // identity mismatch and never signals a bare PID. Descendants are NOT
    // tree-killed (documented PI-03 limitation); that is safe here because the
    // proxy is already down, so any surviving descendant can only reach a dead
    // loopback port and cannot have its traffic decrypted.
    let child_termination = if interrupt.is_some() {
        let outcome = inject::terminate_verified(i64::from(pid), identity.as_deref()).describe();
        // Best-effort bounded reap so the signalled child does not linger as a
        // zombie. Give a SIGTERM-responsive child a moment to exit; do NOT block
        // indefinitely (a child that ignores SIGTERM must not hang teardown —
        // the OS reaps it when this launcher exits shortly after).
        for _ in 0..CHILD_REAP_TRIES {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => std::thread::sleep(LOCK_POLL),
            }
        }
        Some(outcome)
    } else {
        None
    };

    drop(sink); // last Sender clone → writer's rx closes → writer returns
    let _ = writer.join();
    // Dropping `ca` here drops the CertAuthority (leaf cache cleared; the
    // reconstituted CA key is released/zeroized).
    drop(ca);
    drop(trust); // deletes the temp trust files

    // 8. Finalize on the main thread (the writer is done, no concurrent writes).
    //    A lock-interrupted run still has partial data worth attributing.
    let attributions =
        attribution::attribute_session(vault.connection(), &session_id, &params.injected)?;
    // Attribution just backfilled credential_id onto this session's events. If
    // the periodic monitor already rolled up the session's earlier hours while
    // those events were still unattributed, their per-credential buckets are
    // missing and the watermark has moved past them; recompute exactly this
    // session's hour range (watermark untouched) so they are restored.
    if let Ok(Some((first_at, last_at))) = span_of_session_events(vault.connection(), &session_id) {
        let _ = aggregate::reroll_hours(vault.connection(), &first_at, &last_at);
    }
    let _ = aggregate::roll_up(vault.connection(), &clock::now_rfc3339());
    let _ = retention::sweep(vault.connection());
    // Finalize with the honest terminal state. Both calls are compare-and-set on
    // status='running', so they are idempotent and never overwrite a terminal
    // state (a completed run is never relabeled interrupted, and vice versa).
    let interrupt_reason = match interrupt {
        Some(signal) => {
            store::interrupt_session(vault.connection(), &session_id, signal.reason())?;
            Some(signal.reason().to_string())
        }
        None => {
            store::finish_session(vault.connection(), &session_id, exit_code)?;
            None
        }
    };

    Ok(RunOutcome {
        session_id,
        proxy_port: port,
        assessment,
        exit_code,
        attributions,
        interrupt_reason,
        child_termination,
    })
}

/// The `(MIN(at), MAX(at))` timestamp span of a session's recorded events, or
/// `None` if it recorded none.
fn span_of_session_events(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> rusqlite::Result<Option<(String, String)>> {
    conn.query_row(
        "SELECT MIN(at), MAX(at) FROM runtime_request_events WHERE session_id = ?1",
        [session_id],
        |r| {
            let a: Option<String> = r.get(0)?;
            let b: Option<String> = r.get(1)?;
            Ok(a.zip(b))
        },
    )
}

/// The writer thread: owns its own DB connection and persists observed events.
fn run_writer(db_path: &std::path::Path, session_id: &str, rx: Receiver<Msg>) {
    let conn = match api_tracker_core::db::open(db_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let project_id: String = conn
        .query_row(
            "SELECT project_id FROM observation_sessions WHERE id = ?1",
            [session_id],
            |r| r.get(0),
        )
        .unwrap_or_default();

    for msg in rx {
        match msg {
            Msg::Event(o) => {
                let _ = write_event(&conn, session_id, &project_id, &o);
            }
            Msg::Compat {
                check,
                status,
                detail,
            } => {
                let _ = store::record_compat(&conn, session_id, &check, &status, &detail);
            }
            Msg::Partial => {
                let _ = store::set_partial_coverage(&conn, session_id, true);
            }
        }
    }
}

fn write_event(
    conn: &rusqlite::Connection,
    session_id: &str,
    project_id: &str,
    o: &ObservedRequest,
) -> Result<()> {
    let now = clock::now_rfc3339();
    let is_internal = inventory::looks_internal(&o.host);
    let provider = inventory::provider_for_host(&o.host);
    let (service_id, service_known) =
        store::upsert_service(conn, &o.host, provider, is_internal, &now)?;

    // Connection-only events (opaque tunnels) have no endpoint.
    let (endpoint_id, previously_known) =
        if o.method == HttpMethod::Connect && o.path_template == "/:connect" {
            (None, service_known)
        } else {
            let (ep, ep_known) = store::upsert_endpoint(
                conn,
                &service_id,
                o.method,
                &o.path_template,
                o.template_confidence,
                &now,
            )?;
            (Some(ep), ep_known)
        };

    store::insert_request_event(
        conn,
        session_id,
        project_id,
        &service_id,
        endpoint_id.as_deref(),
        &now,
        o,
        previously_known,
    )?;
    Ok(())
}

#[cfg(test)]
mod lock_policy_tests {
    use super::*;

    #[test]
    fn max_run_elapsed_is_auto_lock() {
        let policy = LockPolicy {
            session_file: None,
            max_run: Some(Duration::ZERO),
        };
        // started "now"; ZERO cap is already elapsed.
        assert_eq!(policy.lock_signal(Instant::now()), Some(LockSignal::Auto));
    }

    #[test]
    fn max_run_not_elapsed_is_none() {
        let policy = LockPolicy {
            session_file: None,
            max_run: Some(Duration::from_secs(3600)),
        };
        assert_eq!(policy.lock_signal(Instant::now()), None);
    }

    #[test]
    fn missing_session_file_is_manual_lock() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LockPolicy {
            session_file: Some(dir.path().join("gone.json")),
            max_run: None,
        };
        assert_eq!(policy.lock_signal(Instant::now()), Some(LockSignal::Manual));
    }

    #[test]
    fn default_policy_never_signals() {
        assert_eq!(LockPolicy::default().lock_signal(Instant::now()), None);
    }

    #[test]
    fn reasons_are_stable_non_secret_strings() {
        assert_eq!(LockSignal::Manual.reason(), "vault_locked");
        assert_eq!(LockSignal::Auto.reason(), "auto_lock");
    }
}
