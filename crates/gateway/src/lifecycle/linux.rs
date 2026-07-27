//! Linux systemd USER unit management (ADR 0019 D8).
//!
//! A per-user unit under `~/.config/systemd/user` — never a system-wide
//! service, never root. `WantedBy=default.target` starts it at LOGIN; by
//! default it also STOPS at logout unless the user has lingering enabled.
//! That limitation is REPORTED honestly (`OnlyWhileLoggedIn`) and never
//! "fixed" behind the user's back: `loginctl enable-linger` changes
//! machine-level session behavior and is the user's call.
//!
//! `Restart=on-failure` + the in-process bind-retry loop means a held port
//! degrades visibly instead of tripping systemd's start-rate limiter (a
//! fast-exiting unit would be marked failed permanently — D8).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use api_tracker_core::error::{CoreError, Result};

use super::{CommandRunner, Definition, OsWillRun, RegistrationState, ServiceManager};

pub const UNIT_NAME: &str = "tethra-gateway.service";

pub struct SystemdUser {
    pub data_dir: PathBuf,
    /// `~/.config/systemd/user` on a real host; a temp dir in tests.
    pub unit_dir: PathBuf,
    pub runner: Arc<dyn CommandRunner>,
}

impl SystemdUser {
    pub fn for_host(data_dir: &Path, runner: Arc<dyn CommandRunner>) -> Result<Self> {
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .ok_or_else(|| {
                CoreError::InvalidInput(
                    "neither XDG_CONFIG_HOME nor HOME is set; cannot locate the systemd \
                     user directory"
                        .into(),
                )
            })?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            unit_dir: config_home.join("systemd").join("user"),
            runner,
        })
    }

    /// Render the unit. `ExecStart` uses systemd quoting (double quotes
    /// around each argument that may carry spaces), and every interpolated
    /// path is escaped — see [`systemd_escape`].
    pub fn render_unit(&self, binary: &Path) -> String {
        format!(
            r#"# Written by Tethra (`tethra gateway install`). Removed by
# `tethra gateway uninstall`. No secret ever appears here (D8).
[Unit]
Description=Tethra Local Gateway (loopback-only API observation relay)
Documentation=https://github.com/Arnavtaduvayi/API-Tracker

[Service]
Type=simple
ExecStart="{bin}" gateway serve --service --data-dir "{dir}"
Restart=on-failure
RestartSec=2
# The service resolves everything from --data-dir; no environment needed.

[Install]
WantedBy=default.target
"#,
            bin = systemd_escape(&binary.display().to_string()),
            dir = systemd_escape(&self.data_dir.display().to_string()),
        )
    }

    fn systemctl(&self, args: &[&str]) -> Result<super::RunOutput> {
        let mut full = vec!["--user"];
        full.extend_from_slice(args);
        self.runner.run("systemctl", &full)
    }
}

/// Escape a path for interpolation into a double-quoted `ExecStart` segment.
///
/// `--data-dir` is fully user-controlled, and the macOS renderer already
/// routes both paths through `xml_escape` while this one interpolated them
/// raw. Unescaped, a `"` terminates the quoted segment, a `\` starts a
/// systemd escape sequence, a `%` is a specifier systemd EXPANDS (`%h` is the
/// home directory), and a newline ends the directive — corrupting the unit or
/// injecting into it. Escaping also keeps `parse_exec_start`'s round trip
/// honest, which the install-time foreign-data-dir guard depends on.
fn systemd_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            // A control character cannot survive a single-line directive in
            // any escaped form; drop it rather than emit a broken unit.
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Reverse [`systemd_escape`] for one quoted segment.
fn systemd_unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            '%' if chars.peek() == Some(&'%') => {
                chars.next();
                out.push('%');
            }
            c => out.push(c),
        }
    }
    out
}

/// Pull an ExecStart argument list back out of a unit this module wrote.
fn parse_exec_start(unit: &str) -> Vec<String> {
    let Some(line) = unit
        .lines()
        .find_map(|l| l.trim().strip_prefix("ExecStart="))
    else {
        return Vec::new();
    };
    // Minimal systemd-quoting parser for OUR OWN rendering: double-quoted
    // segments and bare words.
    let mut out = Vec::new();
    let mut rest = line.trim();
    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix('"') {
            // Find the closing quote, skipping an ESCAPED one.
            let mut close = None;
            let bytes = tail.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i += 2,
                    b'"' => {
                        close = Some(i);
                        break;
                    }
                    _ => i += 1,
                }
            }
            let Some(close) = close else { break };
            out.push(systemd_unescape(&tail[..close]));
            rest = tail[close + 1..].trim_start();
        } else {
            match rest.find(char::is_whitespace) {
                Some(i) => {
                    out.push(rest[..i].to_string());
                    rest = rest[i..].trim_start();
                }
                None => {
                    out.push(rest.to_string());
                    rest = "";
                }
            }
        }
    }
    out
}

impl ServiceManager for SystemdUser {
    fn platform(&self) -> &'static str {
        "linux-systemd-user"
    }

    fn definition_path(&self) -> PathBuf {
        self.unit_dir.join(UNIT_NAME)
    }

    fn write_definition(&self, binary: &Path) -> Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(&self.unit_dir).map_err(CoreError::Io)?;
        let path = self.definition_path();
        if std::fs::symlink_metadata(&path).is_ok() {
            std::fs::remove_file(&path).map_err(CoreError::Io)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&path).map_err(CoreError::Io)?;
        f.write_all(self.render_unit(binary).as_bytes())
            .map_err(CoreError::Io)?;
        f.sync_all().map_err(CoreError::Io)?;
        Ok(())
    }

    fn read_definition(&self) -> Result<Option<Definition>> {
        let Ok(content) = std::fs::read_to_string(self.definition_path()) else {
            return Ok(None);
        };
        let args = parse_exec_start(&content);
        let binary = args.first().map(PathBuf::from);
        let data_dir = args
            .iter()
            .position(|a| a == "--data-dir")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from);
        match (binary, data_dir) {
            (Some(binary), Some(data_dir)) => Ok(Some(Definition { binary, data_dir })),
            _ => Ok(None),
        }
    }

    fn remove_definition(&self) -> Result<()> {
        let path = self.definition_path();
        if path.exists() {
            std::fs::remove_file(&path).map_err(CoreError::Io)?;
        }
        // Drop the [Install] symlink and re-read units so nothing stale
        // survives (ordered uninstall, PRODUCT_BEHAVIOR).
        let _ = self.systemctl(&["daemon-reload"]);
        Ok(())
    }

    fn register(&self) -> Result<()> {
        let reload = self.systemctl(&["daemon-reload"])?;
        if !reload.ok() {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user daemon-reload failed: {}",
                reload.stderr.trim()
            )));
        }
        let out = self.systemctl(&["enable", UNIT_NAME])?;
        if !out.ok() {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user enable failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn unregister(&self) -> Result<()> {
        let out = self.systemctl(&["disable", UNIT_NAME])?;
        // Disabling a unit that is not enabled (or no longer exists) is
        // success for an unregister.
        if !out.ok()
            && !out.stderr.contains("does not exist")
            && !out.stderr.contains("No such file")
        {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user disable failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn start(&self) -> Result<()> {
        let out = self.systemctl(&["start", UNIT_NAME])?;
        if !out.ok() {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user start failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        let out = self.systemctl(&["stop", UNIT_NAME])?;
        if !out.ok() && !out.stderr.contains("not loaded") {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user stop failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn restart(&self) -> Result<()> {
        let out = self.systemctl(&["restart", UNIT_NAME])?;
        if !out.ok() {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user restart failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn query(&self) -> RegistrationState {
        let enabled = self
            .systemctl(&["is-enabled", UNIT_NAME])
            .map(|o| o.ok())
            .unwrap_or(false);
        let active = self
            .systemctl(&["is-active", UNIT_NAME])
            .map(|o| o.ok())
            .unwrap_or(false);
        let pid = self
            .systemctl(&["show", UNIT_NAME, "-p", "MainPID", "--value"])
            .ok()
            .and_then(|o| o.stdout.trim().parse::<u32>().ok())
            .filter(|p| *p != 0);
        RegistrationState {
            registered: enabled,
            running: active,
            pid,
            detail: None,
        }
    }

    fn os_will_run(&self, reg: &RegistrationState) -> OsWillRun {
        if !reg.registered {
            return OsWillRun::No;
        }
        // Lingering decides whether the user manager (and this unit)
        // outlives the login session. Reported, never changed.
        let user = std::env::var("USER").unwrap_or_default();
        let linger = self
            .runner
            .run(
                "loginctl",
                &["show-user", &user, "--property=Linger", "--value"],
            )
            .map(|o| o.stdout.trim().eq_ignore_ascii_case("yes"))
            .unwrap_or(false);
        if linger {
            OsWillRun::Yes
        } else {
            OsWillRun::OnlyWhileLoggedIn
        }
    }

    fn prepare_binary(&self, binary: &Path) -> Result<()> {
        let probe = self
            .runner
            .run(&binary.display().to_string(), &["gateway", "service-probe"])?;
        if !probe.ok() || !probe.stdout.contains(super::PROBE_MARKER) {
            return Err(CoreError::InvalidInput(format!(
                "the installed gateway binary did not pass its execution probe \
                 (status {}); not writing a systemd unit that would crash-loop",
                probe.status
            )));
        }
        Ok(())
    }
}
