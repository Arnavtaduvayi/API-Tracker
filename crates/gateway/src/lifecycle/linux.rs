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

use super::{
    CommandRunner, Definition, DefinitionState, OsWillRun, RegistrationState, ServiceManager,
};

/// The unit name used before per-installation namespacing. Kept ONLY for
/// migration (see [`SystemdUser::reclaim_legacy`]); nothing new is
/// registered under it. A fixed name meant `systemctl --user stop` from one
/// Tethra environment stopped another environment's gateway, since the user
/// manager is per-USER, not per-`XDG_CONFIG_HOME` (ZFT-014).
pub const LEGACY_UNIT_NAME: &str = "tethra-gateway.service";

/// The unit name for one installation.
pub fn unit_name_for(installation_id: &str) -> String {
    format!("tethra-gateway-{installation_id}.service")
}

pub struct SystemdUser {
    pub data_dir: PathBuf,
    /// Namespace for the unit name; see [`super::installation_id`].
    pub installation_id: String,
    /// `~/.config/systemd/user` on a real host; a temp dir in tests.
    pub unit_dir: PathBuf,
    pub runner: Arc<dyn CommandRunner>,
}

impl SystemdUser {
    /// Derives the installation id from `data_dir` — always construct
    /// through here (or [`SystemdUser::for_host`]) so the unit name can
    /// never disagree with the directory it serves.
    pub fn new(data_dir: &Path, unit_dir: PathBuf, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            installation_id: super::installation_id(data_dir),
            unit_dir,
            runner,
        }
    }

    /// This installation's systemd unit name.
    pub fn unit_name(&self) -> String {
        unit_name_for(&self.installation_id)
    }

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
        Ok(Self::new(
            data_dir,
            config_home.join("systemd").join("user"),
            runner,
        ))
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

/// Read and parse a unit THIS module wrote, wherever it sits. Shared by the
/// namespaced read and the legacy-migration probe.
///
/// Three states, not two: an absent unit and one we cannot read answered the
/// same `None`, and `ensure_ours` acted on that `None` as "empty slot"
/// (ADR 0026 D2).
fn definition_at(path: &Path) -> DefinitionState {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        // ONLY "no such file" is genuinely absent — that is the clean
        // machine, and install must still work there. Unreadable, not
        // UTF-8, or a directory in the way all mean the same thing: there
        // is something here and we cannot prove whose it is.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DefinitionState::Absent,
        Err(_) => return DefinitionState::Unparseable,
    };
    let args = parse_exec_start(&content);
    let Some(binary) = args.first().map(PathBuf::from) else {
        return DefinitionState::Unparseable;
    };
    let Some(data_dir) = args
        .iter()
        .position(|a| a == "--data-dir")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
    else {
        return DefinitionState::Unparseable;
    };
    DefinitionState::Present(Definition { binary, data_dir })
}

impl ServiceManager for SystemdUser {
    fn platform(&self) -> &'static str {
        "linux-systemd-user"
    }

    fn owned_data_dir(&self) -> &Path {
        &self.data_dir
    }

    fn installation_id(&self) -> &str {
        &self.installation_id
    }

    fn service_name(&self) -> String {
        self.unit_name()
    }

    fn reclaim_legacy(&self) -> Result<Option<String>> {
        let path = self.unit_dir.join(LEGACY_UNIT_NAME);
        // Unreadable or unparseable means we cannot PROVE it is ours, which
        // is the same answer as "someone else's": leave it.
        let DefinitionState::Present(def) = definition_at(&path) else {
            return Ok(None);
        };
        if !super::same_data_dir(&def.data_dir, &self.data_dir) {
            return Ok(None);
        }
        // Ours, under the old global unit name. Stop and disable before the
        // namespaced unit claims the port, then delete the file so login
        // does not start two gateways against one vault.
        let stop = self.systemctl(&["stop", LEGACY_UNIT_NAME])?;
        if !stop.ok() && !stop.stderr.contains("not loaded") {
            return Err(CoreError::InvalidInput(format!(
                "could not stop the legacy unit {LEGACY_UNIT_NAME}: {}",
                stop.stderr.trim()
            )));
        }
        let disable = self.systemctl(&["disable", LEGACY_UNIT_NAME])?;
        if !disable.ok()
            && !disable.stderr.contains("does not exist")
            && !disable.stderr.contains("No such file")
        {
            return Err(CoreError::InvalidInput(format!(
                "could not disable the legacy unit {LEGACY_UNIT_NAME}: {}",
                disable.stderr.trim()
            )));
        }
        std::fs::remove_file(&path).map_err(CoreError::Io)?;
        let _ = self.systemctl(&["daemon-reload"]);
        Ok(Some(LEGACY_UNIT_NAME.to_string()))
    }

    fn definition_path(&self) -> PathBuf {
        self.unit_dir.join(self.unit_name())
    }

    fn write_definition(&self, binary: &Path) -> Result<()> {
        std::fs::create_dir_all(&self.unit_dir).map_err(CoreError::Io)?;
        // Temp + rename: a `daemon-reload` (or a login) that races a
        // truncate-in-place reads half a unit file, which parses as
        // `Unparseable` and locks every later verb out (NEW-02). See
        // `super::atomic_write_definition`.
        super::atomic_write_definition(&self.definition_path(), &self.render_unit(binary))
    }

    fn read_definition_state(&self) -> Result<DefinitionState> {
        Ok(definition_at(&self.definition_path()))
    }

    fn remove_definition(&self) -> Result<()> {
        self.ensure_ours("remove the service definition")?;
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
        // `enable` creates a WantedBy symlink that starts this unit at every
        // login. Doing that for a unit we cannot prove is ours would give
        // another installation's gateway a login slot in this session.
        self.ensure_ours("register")?;
        let reload = self.systemctl(&["daemon-reload"])?;
        if !reload.ok() {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user daemon-reload failed: {}",
                reload.stderr.trim()
            )));
        }
        let out = self.systemctl(&["enable", &self.unit_name()])?;
        if !out.ok() {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user enable failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn unregister(&self) -> Result<()> {
        // The user manager is per-USER: a unit name is a global handle, so
        // prove the unit file names our data directory before disabling it
        // (ZFT-014).
        self.ensure_ours("unregister the service")?;
        let out = self.systemctl(&["disable", &self.unit_name()])?;
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
        // Starting a foreign unit launches another installation's gateway
        // against another vault.
        self.ensure_ours("start")?;
        let out = self.systemctl(&["start", &self.unit_name()])?;
        if !out.ok() {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user start failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        self.ensure_ours("stop the service")?;
        let out = self.systemctl(&["stop", &self.unit_name()])?;
        if !out.ok() && !out.stderr.contains("not loaded") {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user stop failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn restart(&self) -> Result<()> {
        // A restart kills the running process, so it needs the same proof
        // as a stop.
        self.ensure_ours("restart the service")?;
        let out = self.systemctl(&["restart", &self.unit_name()])?;
        if !out.ok() {
            return Err(CoreError::InvalidInput(format!(
                "systemctl --user restart failed: {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn query(&self) -> RegistrationState {
        let unit = self.unit_name();
        let enabled = self
            .systemctl(&["is-enabled", &unit])
            .map(|o| o.ok())
            .unwrap_or(false);
        let active = self
            .systemctl(&["is-active", &unit])
            .map(|o| o.ok())
            .unwrap_or(false);
        let pid = self
            .systemctl(&["show", &unit, "-p", "MainPID", "--value"])
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
