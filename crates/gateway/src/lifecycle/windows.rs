//! Windows per-user login start via the HKCU `Run` registry value.
//!
//! **Compile-validated only.** This code builds and unit-tests on Windows
//! CI, but no Tethra gateway lifecycle has EVER been executed on a real
//! Windows machine. Every status surface reports
//! `RegisteredButNeverValidated`, the docs say the same, and nothing here
//! is claimed as validated (prompt + KNOWN_CONFLICTS C13).
//!
//! Mechanism choice, recorded: the safest per-user login-start mechanism
//! reachable without new dependencies is the
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value — it needs
//! no elevation, no COM, no Service Control Manager, is visible to the
//! user in Task Manager → Startup apps, and is removed by deleting one
//! value. A Scheduled Task would add restart-on-crash but schtasks.exe
//! XML/quoting is fragile and the richer API needs COM (banned
//! dependency); this deviates from OPEN_DECISIONS O5's "foreground only"
//! v1 by shipping the mechanism CODE while still treating the platform as
//! unvalidated. `reg.exe` (always present) performs the registry writes so
//! no registry crate is added.
//!
//! Windows has no control socket (SI-21: attribution refused rather than a
//! TCP fallback), so stop/status work through the pid file plus the
//! listener-identity probe on the forwarding port — stop verifies the
//! listener answers THIS data directory's nonce before it kills the pid,
//! and is force-kill (no graceful drain exists without the control
//! channel; documented).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use api_tracker_core::error::{CoreError, Result};

use super::{CommandRunner, Definition, OsWillRun, RegistrationState, ServiceManager};

pub const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
pub const VALUE_NAME: &str = "TethraGateway";

pub struct RunKey {
    pub data_dir: PathBuf,
    pub runner: Arc<dyn CommandRunner>,
}

impl RunKey {
    pub fn new(data_dir: PathBuf, runner: Arc<dyn CommandRunner>) -> Self {
        Self { data_dir, runner }
    }

    /// The command line stored in the Run value. Windows command-line
    /// quoting: each path wrapped in double quotes. A backslash needs no
    /// escaping inside quotes for `CommandLineToArgvW` UNLESS it immediately
    /// precedes the closing quote, where `\\"` escapes the quote and corrupts
    /// the argument. The old comment asserted paths "never end in a
    /// separator" but nothing enforced it, so `--data-dir C:\\dev\\tethra\\`
    /// (or a bare drive root) produced a value neither Windows nor
    /// `parse_run_value` reads correctly. A trailing separator is now
    /// stripped; a drive root keeps one, doubled, so it survives as a literal.
    pub fn run_value(&self, binary: &Path) -> String {
        format!(
            "\"{}\" gateway serve --service --data-dir \"{}\"",
            Self::quote_safe_path(&binary.display().to_string()),
            Self::quote_safe_path(&self.data_dir.display().to_string()),
        )
    }

    /// Make a path safe to sit inside a double-quoted argument: no trailing
    /// backslash may touch the closing quote. A root path (`C:\\`, `\\`) keeps
    /// a separator — `C:` alone means "the current directory on C:", a
    /// different path — and doubles it, which `CommandLineToArgvW` reads as
    /// one literal backslash.
    fn quote_safe_path(raw: &str) -> String {
        let trimmed = raw.trim_end_matches(['\\', '/']);
        if trimmed.is_empty() || trimmed.ends_with(':') {
            format!("{trimmed}\\\\")
        } else {
            trimmed.to_string()
        }
    }

    /// Parse a stored Run value back into (binary, data_dir).
    pub fn parse_run_value(value: &str) -> Option<Definition> {
        let rest = value.strip_prefix('"')?;
        let close = rest.find('"')?;
        let binary = PathBuf::from(&rest[..close]);
        let after = &rest[close + 1..];
        let marker = "--data-dir \"";
        let start = after.find(marker)? + marker.len();
        let tail = &after[start..];
        let end = tail.find('"')?;
        Some(Definition {
            binary,
            data_dir: PathBuf::from(&tail[..end]),
        })
    }
}

impl ServiceManager for RunKey {
    fn platform(&self) -> &'static str {
        "windows-run-key (compile-validated only; never executed on Windows)"
    }

    fn definition_path(&self) -> PathBuf {
        PathBuf::from(format!(r"{RUN_KEY}\{VALUE_NAME}"))
    }

    fn write_definition(&self, binary: &Path) -> Result<()> {
        let value = self.run_value(binary);
        let out = self.runner.run(
            "reg",
            &[
                "add", RUN_KEY, "/v", VALUE_NAME, "/t", "REG_SZ", "/d", &value, "/f",
            ],
        )?;
        if !out.ok() {
            return Err(CoreError::InvalidInput(format!(
                "reg add failed (status {}): {}",
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn read_definition(&self) -> Result<Option<Definition>> {
        let Ok(out) = self
            .runner
            .run("reg", &["query", RUN_KEY, "/v", VALUE_NAME])
        else {
            return Ok(None);
        };
        if !out.ok() {
            return Ok(None);
        }
        // reg query output: `    TethraGateway    REG_SZ    "C:\...\bin.exe" ...`
        let value = out.stdout.lines().find_map(|l| {
            let t = l.trim();
            if !t.starts_with(VALUE_NAME) {
                return None;
            }
            t.find("REG_SZ")
                .map(|i| t[i + "REG_SZ".len()..].trim().to_string())
        });
        Ok(value.as_deref().and_then(RunKey::parse_run_value))
    }

    fn remove_definition(&self) -> Result<()> {
        let out = self
            .runner
            .run("reg", &["delete", RUN_KEY, "/v", VALUE_NAME, "/f"])?;
        // A missing value is success for a removal.
        if !out.ok() && !out.stderr.contains("unable to find") {
            return Err(CoreError::InvalidInput(format!(
                "reg delete failed (status {}): {}",
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn register(&self) -> Result<()> {
        // The Run value IS the registration; writing it registered it.
        Ok(())
    }

    fn unregister(&self) -> Result<()> {
        self.remove_definition()
    }

    fn start(&self) -> Result<()> {
        let Some(def) = self.read_definition()? else {
            return Err(CoreError::InvalidInput(
                "no gateway service is installed (the Run value is absent)".into(),
            ));
        };
        self.runner.spawn_detached(
            &def.binary.display().to_string(),
            &[
                "gateway",
                "serve",
                "--service",
                "--data-dir",
                &def.data_dir.display().to_string(),
            ],
        )
    }

    fn stop(&self) -> Result<()> {
        // No control socket on Windows: verify the listener answers THIS
        // data directory's nonce before killing the recorded pid, so a
        // recycled pid or a foreign process is never the target.
        let port = crate::store::port_hint(&self.data_dir);
        let Some(port) = port else {
            return Err(CoreError::InvalidInput(
                "no persisted port; cannot verify which process is the gateway. If it \
                 is running, stop it from the terminal it was started in."
                    .into(),
            ));
        };
        match crate::control::verify_listener(&self.data_dir, port) {
            crate::control::ListenerIdentity::Verified { .. } => {}
            crate::control::ListenerIdentity::NoListener => return Ok(()), // already stopped
            other => {
                return Err(CoreError::InvalidInput(format!(
                    "the process on port {port} did not prove it is this data directory's \
                     gateway ({other:?}); refusing to kill it"
                )));
            }
        }
        let pid_raw = std::fs::read_to_string(self.data_dir.join(crate::control::PID_NAME))
            .map_err(CoreError::Io)?;
        let pid: u32 = pid_raw
            .trim()
            .parse()
            .map_err(|_| CoreError::InvalidInput("the gateway pid file is unreadable".into()))?;
        // Force-kill: without the control channel there is no graceful
        // drain on Windows (documented limitation).
        let out = self
            .runner
            .run("taskkill", &["/PID", &pid.to_string(), "/F"])?;
        if !out.ok() {
            return Err(CoreError::InvalidInput(format!(
                "taskkill failed (status {}): {}",
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn restart(&self) -> Result<()> {
        let _ = self.stop();
        self.start()
    }

    fn query(&self) -> RegistrationState {
        let registered = matches!(self.read_definition(), Ok(Some(_)));
        // Liveness through the identity probe (never a bare pid).
        let running = crate::store::port_hint(&self.data_dir)
            .map(|port| {
                matches!(
                    crate::control::verify_listener(&self.data_dir, port),
                    crate::control::ListenerIdentity::Verified { .. }
                )
            })
            .unwrap_or(false);
        let pid = std::fs::read_to_string(self.data_dir.join(crate::control::PID_NAME))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|_| running);
        RegistrationState {
            registered,
            running,
            pid,
            detail: Some("Windows lifecycle is compile-validated only".into()),
        }
    }

    fn os_will_run(&self, reg: &RegistrationState) -> OsWillRun {
        if reg.registered {
            OsWillRun::RegisteredButNeverValidated
        } else {
            OsWillRun::No
        }
    }

    fn prepare_binary(&self, binary: &Path) -> Result<()> {
        let probe = self
            .runner
            .run(&binary.display().to_string(), &["gateway", "service-probe"])?;
        if !probe.ok() || !probe.stdout.contains(super::PROBE_MARKER) {
            return Err(CoreError::InvalidInput(format!(
                "the installed gateway binary did not pass its execution probe \
                 (status {})",
                probe.status
            )));
        }
        Ok(())
    }
}
