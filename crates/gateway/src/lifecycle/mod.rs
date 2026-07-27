//! Per-user OS service lifecycle for the Local Gateway (ADR 0019 D8,
//! TEST_PLAN §9).
//!
//! One engine, three platform managers:
//! - macOS: a LaunchAgent under `~/Library/LaunchAgents` (`bootstrap` /
//!   `bootout` / `kickstart -k`, never `launchctl disable`);
//! - Linux: a systemd USER unit (`WantedBy=default.target`, honest linger
//!   reporting, never a system-wide service);
//! - Windows: an HKCU `Run` registry value (per-user login start; no admin,
//!   no Service Control Manager). Windows support is COMPILE-VALIDATED ONLY
//!   — it has never been executed on a real Windows machine, and every
//!   status surface says so.
//!
//! Install strategy (D8): the service binary is a FRESH BYTE-WRITE of the
//! running CLI binary into `<data-dir>/bin/tethra-gateway-<version>` —
//! never `fs::copy`, which on macOS propagates `com.apple.quarantine` and
//! produces a launchd crash loop with no interactive Gatekeeper bypass
//! (KNOWN_CONFLICTS C12). After the write the quarantine attribute is
//! removed and the binary is EXEC-PROBED before any service definition is
//! written: if Gatekeeper kills the probe, enable fails honestly toward
//! foreground mode instead of installing a service that can never run.
//!
//! The resolved data directory is baked into the service argv
//! (`--data-dir`): service managers inherit no shell environment, and a
//! `TETHRA_DIR` that resolves differently at login would silently split the
//! vault. No secret ever appears in argv, the definition file, or the
//! registry.
//!
//! Every service name is NAMESPACED by [`installation_id`], and every
//! destructive verb proves the definition it is about to touch belongs to
//! this data directory ([`ServiceManager::ensure_ours`]). See
//! `installation_id` for why a fixed global name was a defect and not a
//! simplification.
//!
//! Every OS interaction goes through [`CommandRunner`], so unit tests run
//! against a mock in temporary directories — `cargo test` never installs,
//! starts, or stops a real service.

pub mod linux;
pub mod macos;
pub mod windows;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use api_tracker_core::error::{CoreError, Result};
use rusqlite::Connection;
use serde::Serialize;

use crate::envlink;
use crate::routes;
use crate::store;

/// What the exec probe must print (the CLI's hidden `gateway service-probe`
/// subcommand). Proves the copied binary actually executes under this OS
/// before a service definition points at it.
pub const PROBE_MARKER: &str = "tethra-gateway-service-probe";

/// Hex characters of the installation hash kept in a service name. 12 hex
/// = 48 bits: short enough to stay readable in `launchctl print` output and
/// a systemd unit file name, far more than enough to separate the handful
/// of Tethra environments one user account can hold.
const INSTALLATION_ID_LEN: usize = 12;

/// A short, stable identity for ONE Tethra installation, derived from the
/// CANONICALIZED data directory.
///
/// Every login-start mechanism this module drives is a single per-user
/// namespace: one launchd label, one systemd user unit name, one HKCU `Run`
/// value. While those names were fixed constants, a second Tethra
/// environment — its own `TETHRA_DIR`, even its own `HOME` — addressed the
/// FIRST environment's job, because `launchctl`'s `gui/<uid>` domain is the
/// real session domain no matter which `HOME` the plist was read from. That
/// environment saw no plist of its own, wrote one, hit "already
/// bootstrapped", and booted the OTHER installation's running gateway out
/// (ZFT-014 — observed, not theoretical). Deriving the name from the data
/// directory gives every installation its own slot.
///
/// Canonicalized so that `/tmp/x` and `/private/tmp/x`, or a path reached
/// through a symlinked home, are ONE identity rather than two competing
/// services. A path that cannot be canonicalized (it does not exist yet)
/// falls back to its literal form, which is stable for exactly as long as
/// it stays uncreated — installs always run against a data directory that
/// exists.
pub fn installation_id(data_dir: &Path) -> String {
    let resolved = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    // `derive_key`, not `hash`. The input is a filesystem path rather than
    // credential material, so this is a domain-separated derivation, and
    // saying so in the primitive keeps the crate's blanket ban on unkeyed
    // `blake3::hash` intact (`tests/privacy_canaries.rs`) instead of
    // carving an exception into a rule that exists to stop a stolen
    // database becoming an offline guess-confirmation oracle.
    let key = blake3::derive_key(
        "tethra gateway service installation id v1",
        resolved.as_os_str().as_encoded_bytes(),
    );
    let hex: String = key
        .iter()
        .take(INSTALLATION_ID_LEN.div_ceil(2))
        .map(|b| format!("{b:02x}"))
        .collect();
    hex[..INSTALLATION_ID_LEN].to_string()
}

/// Whether two `--data-dir` values name the SAME directory.
///
/// Every ownership proof runs through this, so it is deliberately
/// conservative: equal literal paths, or two paths that canonicalize to the
/// same real directory. Anything it cannot POSITIVELY prove equal is
/// treated as foreign — the failure mode of a false "yes" here is tearing
/// down another installation's gateway.
pub fn same_data_dir(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Runs external commands. The host implementation shells out; tests
/// substitute a recorder so no real `launchctl`/`systemctl`/`reg` runs.
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> Result<RunOutput>;
    /// Spawn without waiting (Windows manual start). The child must outlive
    /// the caller.
    fn spawn_detached(&self, program: &str, args: &[&str]) -> Result<()>;
}

#[derive(Debug, Clone, Default)]
pub struct RunOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl RunOutput {
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

/// The real runner.
pub struct HostRunner;

impl CommandRunner for HostRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<RunOutput> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(CoreError::Io)?;
        Ok(RunOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn spawn_detached(&self, program: &str, args: &[&str]) -> Result<()> {
        std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(CoreError::Io)?;
        Ok(())
    }
}

/// A parsed service definition: where it points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Definition {
    pub binary: PathBuf,
    pub data_dir: PathBuf,
}

/// Whether the OS will actually run the service, reported honestly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OsWillRun {
    /// Registered with the OS start mechanism.
    Yes,
    /// Linux: the unit starts at LOGIN only; without lingering it stops at
    /// logout. Reported, never auto-"fixed" (no `loginctl enable-linger`).
    OnlyWhileLoggedIn,
    /// Registered, but the platform has never executed this code path
    /// (Windows: compile-validated only).
    RegisteredButNeverValidated,
    /// Not registered.
    No,
    /// Could not determine (the query command failed).
    Unknown { why: String },
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RegistrationState {
    pub registered: bool,
    pub running: bool,
    pub pid: Option<u32>,
    pub detail: Option<String>,
}

/// One platform's service mechanics. Everything is same-user; nothing here
/// ever requires or requests elevation.
pub trait ServiceManager: Send + Sync {
    fn platform(&self) -> &'static str;
    /// The ONLY data directory this manager may act on. Every destructive
    /// verb proves the definition it is about to touch points here.
    fn owned_data_dir(&self) -> &Path;
    /// The [`installation_id`] this manager's service name is namespaced by.
    fn installation_id(&self) -> &str;
    /// The resolved OS-level name: launchd label, systemd unit file name,
    /// or HKCU `Run` value name. Surfaced in status so diagnostics say WHICH
    /// service is being controlled.
    fn service_name(&self) -> String;
    /// Unload and delete a LEGACY (pre-namespacing) definition, but only
    /// when it points at OUR data directory; returns the legacy name when
    /// one was reclaimed. A legacy definition belonging to a different data
    /// directory is left completely alone — it is another installation's
    /// production gateway, and the migration is not an excuse to touch it.
    fn reclaim_legacy(&self) -> Result<Option<String>>;
    fn definition_path(&self) -> PathBuf;
    /// Render + write the definition (0600 where the platform has modes).
    fn write_definition(&self, binary: &Path) -> Result<()>;
    /// Parse the existing definition, if any.
    fn read_definition(&self) -> Result<Option<Definition>>;
    fn remove_definition(&self) -> Result<()>;
    /// Make the OS start it at login/boot-of-session.
    fn register(&self) -> Result<()>;
    fn unregister(&self) -> Result<()>;
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn restart(&self) -> Result<()>;
    fn query(&self) -> RegistrationState;
    fn os_will_run(&self, reg: &RegistrationState) -> OsWillRun;
    /// Platform preparation after the byte-write: de-quarantine + exec
    /// probe on macOS, exec probe elsewhere. MUST run before any
    /// definition is written.
    fn prepare_binary(&self, binary: &Path) -> Result<()>;

    /// OWNERSHIP PROOF, run before every destructive verb (`unregister`,
    /// `stop`, `restart`, `remove_definition`, and the bootout inside
    /// `register`'s retry).
    ///
    /// Namespacing alone is not proof: a definition can be moved, edited by
    /// hand, or left behind by a data directory that was relocated, and the
    /// verb then lands on whatever job currently answers to our name. So we
    /// re-read the definition we are about to act on and require it to
    /// point at our own data directory. An absent definition is fine —
    /// there is nothing to destroy — but a foreign one is refused by name
    /// rather than silently obeyed (ZFT-014).
    fn ensure_ours(&self, verb: &str) -> Result<()> {
        let Some(def) = self.read_definition()? else {
            return Ok(());
        };
        if same_data_dir(&def.data_dir, self.owned_data_dir()) {
            return Ok(());
        }
        Err(CoreError::InvalidInput(format!(
            "refusing to {verb}: the service {} belongs to a different Tethra data \
             directory ({}), not this one ({}). Run the command from that installation.",
            self.service_name(),
            def.data_dir.display(),
            self.owned_data_dir().display(),
        )))
    }
}

/// The engine: shared orchestration over a platform manager.
pub struct Lifecycle {
    pub data_dir: PathBuf,
    pub manager: Box<dyn ServiceManager>,
    pub runner: Arc<dyn CommandRunner>,
    /// The version stamped into the installed binary's file name.
    pub version: String,
}

/// The service status every frontend (CLI status/doctor, desktop panel)
/// renders from. All facts, no interpretation.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceStatus {
    pub platform: &'static str,
    /// WHICH installation these facts describe: the short id derived from
    /// this data directory ([`installation_id`]). Two Tethra environments
    /// on one account report different ids and control different services.
    pub installation_id: String,
    /// The resolved OS-level service name that id controls (launchd label,
    /// systemd unit name, or HKCU `Run` value name) — the string a user or
    /// support request needs to inspect the job by hand.
    pub service_name: String,
    /// The definition file / registry value exists.
    pub installed: bool,
    pub definition_path: String,
    pub definition: Option<Definition>,
    /// The definition's `--data-dir` equals ours. False means a stale or
    /// foreign install owns the login slot.
    pub matches_data_dir: bool,
    pub binary_exists: bool,
    /// Version parsed from the installed binary's file name.
    pub binary_version: Option<String>,
    pub registered: bool,
    pub running: bool,
    pub pid: Option<u32>,
    pub os_will_run: OsWillRun,
    /// Every artifact the feature owns on this machine (PRODUCT_BEHAVIOR:
    /// status lists what uninstall will remove).
    pub owned_artifacts: Vec<String>,
    pub notes: Vec<String>,
}

/// "Nothing is known" — the shape every placeholder/fixture starts from, so
/// a new fact added to [`ServiceStatus`] does not have to be spelled out at
/// each construction site (and cannot be silently forgotten there).
impl Default for ServiceStatus {
    fn default() -> Self {
        Self {
            platform: "unknown",
            installation_id: String::new(),
            service_name: String::new(),
            installed: false,
            definition_path: String::new(),
            definition: None,
            matches_data_dir: false,
            binary_exists: false,
            binary_version: None,
            registered: false,
            running: false,
            pid: None,
            os_will_run: OsWillRun::Unknown {
                why: "not determined".into(),
            },
            owned_artifacts: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// What install did, for honest reporting.
#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    pub binary: String,
    pub definition: String,
    pub started: bool,
    pub pruned_binaries: Vec<String>,
    pub notes: Vec<String>,
}

/// Per-project result of the disable/uninstall `.env` restore pass.
#[derive(Debug, Clone, Serialize)]
pub struct DisableReport {
    pub stopped: bool,
    pub unregistered: bool,
    pub env_restores: Vec<envlink::UnlinkReport>,
    /// Links that could not be restored (kept for retry).
    pub incomplete_restores: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UninstallReport {
    pub disable: DisableReport,
    pub removed_paths: Vec<String>,
    pub notes: Vec<String>,
}

pub fn bin_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("bin")
}

pub fn logs_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("logs")
}

pub fn binary_name(version: &str) -> String {
    format!("tethra-gateway-{version}{}", std::env::consts::EXE_SUFFIX)
}

/// Parse the version back out of an installed binary file name.
pub fn version_of_binary_name(name: &str) -> Option<String> {
    let stem = name
        .strip_suffix(std::env::consts::EXE_SUFFIX)
        .unwrap_or(name);
    stem.strip_prefix("tethra-gateway-").map(|v| v.to_string())
}

/// Where a bundled helper CLI would sit next to the given executable
/// (Tauri's `externalBin` places the sidecar beside the main binary on
/// every platform: `Contents/MacOS/tethra` inside a macOS app bundle,
/// alongside the executable on Linux/Windows). Pure path derivation — the
/// caller decides whether the file exists and answers the exec probe.
pub fn bundled_helper_candidate(current_exe: &Path) -> Option<PathBuf> {
    let dir = current_exe.parent()?;
    Some(dir.join(format!("tethra{}", std::env::consts::EXE_SUFFIX)))
}

/// Whether a candidate helper binary actually runs on this machine and is
/// the real Tethra CLI: it must exit 0 from the hidden
/// `gateway service-probe` subcommand and print [`PROBE_MARKER`]. This is
/// the same gate `prepare_binary` applies before a service definition may
/// point at a copied binary — a missing, corrupted (unexecutable), or
/// impostor file all fail it; a version-drifted but genuine helper passes
/// (drift is surfaced by doctor and repaired by the tracking apply step,
/// never hidden at discovery time).
pub fn helper_answers_probe(runner: &dyn CommandRunner, candidate: &Path) -> bool {
    if !candidate.is_file() {
        return false;
    }
    runner
        .run(
            &candidate.display().to_string(),
            &["gateway", "service-probe"],
        )
        .map(|out| out.ok() && out.stdout.contains(PROBE_MARKER))
        .unwrap_or(false)
}

/// Fresh byte-write of `src` to `dst` (never `fs::copy`: quarantine and
/// other metadata must NOT propagate — C12). Creates the parent, replaces
/// any previous file, sets 0755 on Unix.
pub fn fresh_byte_write(src: &Path, dst: &Path) -> Result<()> {
    use std::io::Write;
    let bytes = std::fs::read(src).map_err(CoreError::Io)?;
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(CoreError::Io)?;
    }
    // Remove first: overwriting an executing binary fails on some
    // platforms, and a symlink at the target must never be followed.
    if std::fs::symlink_metadata(dst).is_ok() {
        std::fs::remove_file(dst).map_err(CoreError::Io)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o755);
    }
    let mut f = options.open(dst).map_err(CoreError::Io)?;
    f.write_all(&bytes).map_err(CoreError::Io)?;
    f.sync_all().map_err(CoreError::Io)?;
    Ok(())
}

impl Lifecycle {
    /// The engine for THIS host platform, with the real runner.
    pub fn for_host(data_dir: &Path) -> Result<Self> {
        let runner: Arc<dyn CommandRunner> = Arc::new(HostRunner);
        let version = env!("CARGO_PKG_VERSION").to_string();
        let manager: Box<dyn ServiceManager> = {
            #[cfg(target_os = "macos")]
            {
                Box::new(macos::LaunchAgent::for_host(data_dir, runner.clone())?)
            }
            #[cfg(all(unix, not(target_os = "macos")))]
            {
                Box::new(linux::SystemdUser::for_host(data_dir, runner.clone())?)
            }
            #[cfg(windows)]
            {
                Box::new(windows::RunKey::new(data_dir.to_path_buf(), runner.clone()))
            }
        };
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            manager,
            runner,
            version,
        })
    }

    pub fn installed_binary_path(&self) -> PathBuf {
        bin_dir(&self.data_dir).join(binary_name(&self.version))
    }

    /// Install (or re-install) and start the service from `source_binary`
    /// (normally the running CLI binary). Steps, in the D8 order:
    /// byte-write → prepare (de-quarantine + exec probe) → definition →
    /// register → start. Refuses when an existing definition points at a
    /// DIFFERENT data directory unless `force` (that slot belongs to
    /// another vault).
    pub fn install(&self, source_binary: &Path, force: bool) -> Result<InstallReport> {
        let mut notes = Vec::new();
        match self.manager.read_definition()? {
            Some(existing) => {
                if !same_data_dir(&existing.data_dir, &self.data_dir) && !force {
                    return Err(CoreError::InvalidInput(format!(
                        "a Tethra gateway service is already installed for a different data \
                         directory ({}). Uninstall it first, or pass --force to replace it.",
                        existing.data_dir.display()
                    )));
                }
                if !same_data_dir(&existing.data_dir, &self.data_dir) {
                    notes.push(format!(
                        "replaced a service that pointed at {}",
                        existing.data_dir.display()
                    ));
                }
            }
            // A definition file we cannot PARSE is not the same thing as no
            // definition. `reclaim_legacy` already says so in as many words
            // — "unreadable means we cannot prove it is ours, which is the
            // same answer as someone else's: leave it" — and the same rule
            // has to hold here, or an unparseable plist in our slot gets
            // silently unlinked and overwritten.
            None if self.manager.definition_path().exists() && !force => {
                return Err(CoreError::InvalidInput(format!(
                    "{} already exists but could not be parsed as a Tethra service \
                     definition. Tethra will not overwrite a definition it cannot prove is \
                     its own; inspect or remove the file, or pass --force.",
                    self.manager.definition_path().display()
                )));
            }
            None if self.manager.definition_path().exists() => {
                notes.push(format!(
                    "replaced an unparseable definition at {}",
                    self.manager.definition_path().display()
                ));
            }
            None => {}
        }

        let target = self.installed_binary_path();
        fresh_byte_write(source_binary, &target)?;
        self.manager.prepare_binary(&target)?;
        std::fs::create_dir_all(logs_dir(&self.data_dir)).map_err(CoreError::Io)?;
        // Whether a service is ALREADY running decides start vs restart: on
        // an upgrade, `start` leaves the old process alive against the old
        // binary — which `prune_old_binaries` is about to delete. Query
        // before re-registering, since registering can itself change the
        // answer.
        let was_running = self.manager.query().running;
        self.manager.write_definition(&target)?;
        // Only now — probe passed, new definition on disk — do we retire a
        // pre-namespacing service that pointed at THIS data directory.
        // Earlier would mean a failed probe left the user with no gateway at
        // all; later would mean two definitions racing for the same port at
        // next login. A legacy service owned by ANOTHER data directory is
        // never touched, and its presence is not an error (ZFT-014).
        // Roll the new definition back if migration or registration fails.
        // On macOS launchd loads EVERY plist in ~/Library/LaunchAgents with
        // RunAtLoad at login, bootstrapped or not, so leaving our new plist
        // beside an un-retired legacy one would give a single vault TWO
        // gateways fighting over one port at the next login — with no
        // warning and no way back.
        let rollback = |e: CoreError| -> CoreError {
            let _ = self.manager.remove_definition();
            e
        };
        match self.manager.reclaim_legacy() {
            Ok(Some(legacy)) => notes.push(format!(
                "migrated the pre-namespacing service {legacy} to {}; one service per \
                 data directory now",
                self.manager.service_name()
            )),
            Ok(None) => {}
            Err(e) => return Err(rollback(e)),
        }
        if let Err(e) = self.manager.register() {
            return Err(rollback(e));
        }
        let started = if was_running {
            self.manager.restart()
        } else {
            self.manager.start()
        };
        if let Err(e) = started {
            // Registration succeeded, so the definition is live; unregister
            // before removing it, or launchd keeps a job pointing at a file
            // that no longer exists.
            let _ = self.manager.unregister();
            return Err(rollback(e));
        }
        let pruned = self.prune_old_binaries(&target)?;
        Ok(InstallReport {
            binary: target.display().to_string(),
            definition: self.manager.definition_path().display().to_string(),
            started: true,
            pruned_binaries: pruned,
            notes,
        })
    }

    /// Remove every OTHER version's binary once the new one is installed
    /// and started (upgrade hygiene; the running old process keeps its
    /// unlinked inode on Unix until it exits).
    fn prune_old_binaries(&self, keep: &Path) -> Result<Vec<String>> {
        let mut pruned = Vec::new();
        let dir = bin_dir(&self.data_dir);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Ok(pruned);
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path != keep
                && version_of_binary_name(&name).is_some()
                && std::fs::remove_file(&path).is_ok()
            {
                pruned.push(name);
            }
        }
        Ok(pruned)
    }

    /// Stop + unregister + restore linked `.env` files (unless `keep_env`).
    /// Binaries and DB rows stay — this is "off", not "gone".
    pub fn disable(&self, conn: &Connection, keep_env: bool) -> Result<DisableReport> {
        let mut notes = Vec::new();
        // The stop error is the one that tells a user their environment does
        // not own this slot; swallowing it left `service stopped: false`
        // with no reason attached.
        let stop_ok = match self.manager.stop() {
            Ok(()) => true,
            Err(e) => {
                notes.push(format!("stop: {e}"));
                false
            }
        };
        let unregister_ok = match self.manager.unregister() {
            Ok(()) => true,
            Err(e) => {
                notes.push(format!("unregister: {e}"));
                false
            }
        };
        if let Err(e) = self.manager.remove_definition() {
            notes.push(format!("definition removal: {e}"));
        }
        // Uninstall must leave nothing of OURS behind and nothing of anyone
        // else's disturbed: a pre-namespacing definition goes only if it
        // points here.
        match self.manager.reclaim_legacy() {
            Ok(Some(legacy)) => notes.push(format!(
                "also removed the pre-namespacing service {legacy}, which pointed at this \
                 data directory"
            )),
            Ok(None) => {}
            Err(e) => notes.push(format!("legacy definition removal: {e}")),
        }

        let mut env_restores = Vec::new();
        let mut incomplete = 0usize;
        if keep_env {
            notes.push("linked .env files left in place (--keep-env)".into());
        } else {
            for link in routes::list_project_links(conn)? {
                if link.prior_env_json.is_none() {
                    continue; // nothing was ever written for this link
                }
                match envlink::unlink(conn, &link.project_id, &link.route_prefix) {
                    Ok(report) => {
                        if !report.complete {
                            incomplete += 1;
                        }
                        env_restores.push(report);
                    }
                    Err(e) => {
                        incomplete += 1;
                        notes.push(format!(
                            "restore failed for project {} route {}: {e}",
                            link.project_id, link.route_prefix
                        ));
                    }
                }
            }
        }

        let mut config = store::load_config(conn)?;
        config.enabled = false;
        store::save_config(conn, &config)?;

        Ok(DisableReport {
            stopped: stop_ok,
            unregistered: unregister_ok,
            env_restores,
            incomplete_restores: incomplete,
            notes,
        })
    }

    /// The full ordered uninstall (PRODUCT_BEHAVIOR): disable (with `.env`
    /// restore) → delete `<data-dir>/bin` (all versions) → delete logs →
    /// delete stale runtime files. Database rows are KEPT — observed
    /// history is user data; a separate purge exists for that.
    pub fn uninstall(&self, conn: &Connection, keep_env: bool) -> Result<UninstallReport> {
        let disable = self.disable(conn, keep_env)?;
        let mut removed = Vec::new();
        let mut notes = Vec::new();
        for dir in [bin_dir(&self.data_dir), logs_dir(&self.data_dir)] {
            if dir.exists() {
                match std::fs::remove_dir_all(&dir) {
                    Ok(()) => removed.push(dir.display().to_string()),
                    Err(e) => notes.push(format!("could not remove {}: {e}", dir.display())),
                }
            }
        }
        for file in [
            crate::control::SOCKET_NAME,
            crate::control::NONCE_NAME,
            crate::control::PID_NAME,
        ] {
            let p = self.data_dir.join(file);
            if p.exists() && std::fs::remove_file(&p).is_ok() {
                removed.push(p.display().to_string());
            }
        }
        Ok(UninstallReport {
            disable,
            removed_paths: removed,
            notes,
        })
    }

    /// Facts for status/doctor.
    pub fn status(&self) -> ServiceStatus {
        let definition_path = self.manager.definition_path();
        let definition = self.manager.read_definition().ok().flatten();
        let installed = definition.is_some();
        let matches = definition
            .as_ref()
            .map(|d| same_data_dir(&d.data_dir, &self.data_dir))
            .unwrap_or(false);
        let binary_exists = definition
            .as_ref()
            .map(|d| d.binary.exists())
            .unwrap_or(false);
        let binary_version = definition.as_ref().and_then(|d| {
            d.binary
                .file_name()
                .and_then(|n| version_of_binary_name(&n.to_string_lossy()))
        });
        let reg = self.manager.query();
        let os_will_run = if installed {
            self.manager.os_will_run(&reg)
        } else {
            OsWillRun::No
        };

        let mut owned = vec![definition_path.display().to_string()];
        if let Ok(entries) = std::fs::read_dir(bin_dir(&self.data_dir)) {
            for e in entries.flatten() {
                owned.push(e.path().display().to_string());
            }
        }
        let logs = logs_dir(&self.data_dir);
        if logs.exists() {
            owned.push(logs.display().to_string());
        }

        let mut notes = Vec::new();
        if installed && !matches {
            notes.push(
                "the installed service points at a DIFFERENT data directory; this vault's \
                 gateway will not start at login"
                    .into(),
            );
        }
        if installed && !binary_exists {
            notes.push(
                "the service definition points at a binary that no longer exists (moved or \
                 cleaned); run `tethra gateway repair`"
                    .into(),
            );
        }

        ServiceStatus {
            platform: self.manager.platform(),
            installation_id: self.manager.installation_id().to_string(),
            service_name: self.manager.service_name(),
            installed,
            definition_path: definition_path.display().to_string(),
            definition,
            matches_data_dir: matches,
            binary_exists,
            binary_version,
            registered: reg.registered,
            running: reg.running,
            pid: reg.pid,
            os_will_run,
            owned_artifacts: owned,
            notes,
        }
    }

    pub fn start(&self) -> Result<()> {
        self.manager.start()
    }

    pub fn stop(&self) -> Result<()> {
        self.manager.stop()
    }

    pub fn restart(&self) -> Result<()> {
        self.manager.restart()
    }

    /// Re-align everything with THIS binary and THIS data directory:
    /// re-byte-write, re-prepare, rewrite the definition, re-register, and
    /// restart. Fixes moved binaries, stale definitions, and version
    /// mismatches in one pass.
    pub fn repair(&self, source_binary: &Path) -> Result<InstallReport> {
        // Deliberately NOT forced. Repair means "our own installed helper
        // drifted from this build"; it is reached automatically from the
        // `tethra track` apply path, with no user decision behind it. A
        // forced repair would walk straight past the different-data-dir
        // refusal, write our definition over another installation's, and
        // then — because the slot now reads as ours — pass the ownership
        // proof on the way to booting that installation's gateway out.
        // That is ZFT-014 again, reached from the automatic path.
        self.install(source_binary, false)
    }
}
