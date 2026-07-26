//! macOS LaunchAgent management (ADR 0019 D8).
//!
//! A per-user LaunchAgent — never a root LaunchDaemon. Registration uses
//! the modern `launchctl bootstrap gui/<uid> <plist>` / `bootout
//! gui/<uid>/<label>` / `kickstart -k` verbs; `launchctl disable` is never
//! used (it writes persistent per-service override state that survives
//! uninstall and confuses reinstalls). The plist is written 0600 with
//! `RunAtLoad`, `KeepAlive={Crashed:true}` (a CLEAN exit is terminal — the
//! service self-exits when its data directory disappears and must not be
//! respawned), `ProcessType Background`, and stdout/stderr appended to
//! `<data-dir>/logs/gateway.log`.
//!
//! The install appears in System Settings → General → Login Items as a
//! background item; the consent flow discloses this (BTM disclosure,
//! PRODUCT_BEHAVIOR).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use api_tracker_core::error::{CoreError, Result};

use super::{CommandRunner, Definition, OsWillRun, RegistrationState, ServiceManager};

/// The LaunchAgent label. Fixed (one login slot per user), consistent with
/// the preserved `dev.api-tracker.*` identifier family (rebrand policy).
pub const LABEL: &str = "dev.api-tracker.gateway";

pub struct LaunchAgent {
    pub data_dir: PathBuf,
    /// `~/Library/LaunchAgents` on a real host; a temp dir in tests.
    pub launch_agents_dir: PathBuf,
    /// The user's numeric uid for the `gui/<uid>` domain target.
    pub uid: String,
    pub runner: Arc<dyn CommandRunner>,
}

impl LaunchAgent {
    pub fn for_host(data_dir: &Path, runner: Arc<dyn CommandRunner>) -> Result<Self> {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            CoreError::InvalidInput("HOME is not set; cannot locate ~/Library/LaunchAgents".into())
        })?;
        let uid_out = runner.run("id", &["-u"])?;
        if !uid_out.ok() {
            return Err(CoreError::InvalidInput(
                "could not determine the current uid (`id -u` failed)".into(),
            ));
        }
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            launch_agents_dir: PathBuf::from(home).join("Library").join("LaunchAgents"),
            uid: uid_out.stdout.trim().to_string(),
            runner,
        })
    }

    fn domain_target(&self) -> String {
        format!("gui/{}", self.uid)
    }

    fn service_target(&self) -> String {
        format!("gui/{}/{LABEL}", self.uid)
    }

    /// Render the plist. Paths are XML-escaped; argv array form means
    /// spaces in paths need no quoting.
    pub fn render_plist(&self, binary: &Path) -> String {
        let log = super::logs_dir(&self.data_dir).join("gateway.log");
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{bin}</string>
		<string>gateway</string>
		<string>serve</string>
		<string>--service</string>
		<string>--data-dir</string>
		<string>{dir}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>Crashed</key>
		<true/>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>{log}</string>
	<key>StandardErrorPath</key>
	<string>{log}</string>
</dict>
</plist>
"#,
            label = LABEL,
            bin = xml_escape(&binary.display().to_string()),
            dir = xml_escape(&self.data_dir.display().to_string()),
            log = xml_escape(&log.display().to_string()),
        )
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Pull the `<string>` values out of the ProgramArguments array. A
/// deliberately narrow parser: it reads only plists THIS module wrote.
fn parse_program_arguments(plist: &str) -> Vec<String> {
    let Some(args_start) = plist.find("<key>ProgramArguments</key>") else {
        return Vec::new();
    };
    let Some(array_end) = plist[args_start..].find("</array>") else {
        return Vec::new();
    };
    let section = &plist[args_start..args_start + array_end];
    let mut out = Vec::new();
    let mut rest = section;
    while let Some(open) = rest.find("<string>") {
        let tail = &rest[open + "<string>".len()..];
        let Some(close) = tail.find("</string>") else {
            break;
        };
        out.push(xml_unescape(&tail[..close]));
        rest = &tail[close..];
    }
    out
}

impl ServiceManager for LaunchAgent {
    fn platform(&self) -> &'static str {
        "macos-launch-agent"
    }

    fn definition_path(&self) -> PathBuf {
        self.launch_agents_dir.join(format!("{LABEL}.plist"))
    }

    fn write_definition(&self, binary: &Path) -> Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(&self.launch_agents_dir).map_err(CoreError::Io)?;
        let path = self.definition_path();
        // Fresh 0600 write; never follow a symlink planted at the path.
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
        f.write_all(self.render_plist(binary).as_bytes())
            .map_err(CoreError::Io)?;
        f.sync_all().map_err(CoreError::Io)?;
        Ok(())
    }

    fn read_definition(&self) -> Result<Option<Definition>> {
        let path = self.definition_path();
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Ok(None);
        };
        let args = parse_program_arguments(&content);
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
        Ok(())
    }

    fn register(&self) -> Result<()> {
        let plist = self.definition_path().display().to_string();
        let out = self
            .runner
            .run("launchctl", &["bootstrap", &self.domain_target(), &plist])?;
        // Code 5 / "already bootstrapped" is fine — kickstart will pick up
        // the (possibly rewritten) definition on restart.
        if !out.ok() && !out.stderr.contains("already bootstrapped") && out.status != 5 {
            return Err(CoreError::InvalidInput(format!(
                "launchctl bootstrap failed (status {}): {}",
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn unregister(&self) -> Result<()> {
        let out = self
            .runner
            .run("launchctl", &["bootout", &self.service_target()])?;
        // Not-loaded is success for an unregister.
        if !out.ok()
            && !out.stderr.contains("No such process")
            && !out.stderr.contains("not find")
            && out.status != 3
        {
            return Err(CoreError::InvalidInput(format!(
                "launchctl bootout failed (status {}): {}",
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn start(&self) -> Result<()> {
        let out = self
            .runner
            .run("launchctl", &["kickstart", &self.service_target()])?;
        if !out.ok() {
            return Err(CoreError::InvalidInput(format!(
                "launchctl kickstart failed (status {}): {}",
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        // bootout stops AND unloads until next login; for a plain stop we
        // bootout then leave the plist in place — RunAtLoad re-registers at
        // next login, and `start`/`restart` re-bootstraps explicitly.
        self.unregister()
    }

    fn restart(&self) -> Result<()> {
        // kickstart -k kills a running instance and starts a fresh one; if
        // the service is not currently bootstrapped, bootstrap it first.
        let out = self
            .runner
            .run("launchctl", &["kickstart", "-k", &self.service_target()])?;
        if out.ok() {
            return Ok(());
        }
        self.register()?;
        let retry = self
            .runner
            .run("launchctl", &["kickstart", "-k", &self.service_target()])?;
        if !retry.ok() {
            return Err(CoreError::InvalidInput(format!(
                "launchctl kickstart -k failed (status {}): {}",
                retry.status,
                retry.stderr.trim()
            )));
        }
        Ok(())
    }

    fn query(&self) -> RegistrationState {
        let Ok(out) = self
            .runner
            .run("launchctl", &["print", &self.service_target()])
        else {
            return RegistrationState {
                detail: Some("launchctl print could not run".into()),
                ..RegistrationState::default()
            };
        };
        if !out.ok() {
            return RegistrationState::default();
        }
        let running = out
            .stdout
            .lines()
            .any(|l| l.trim().starts_with("state") && l.contains("running"));
        let pid = out.stdout.lines().find_map(|l| {
            let t = l.trim();
            t.strip_prefix("pid = ").and_then(|v| v.trim().parse().ok())
        });
        RegistrationState {
            registered: true,
            running,
            pid,
            detail: None,
        }
    }

    fn os_will_run(&self, reg: &RegistrationState) -> OsWillRun {
        if reg.registered {
            OsWillRun::Yes
        } else if self.definition_path().exists() {
            // Plist present but not bootstrapped: RunAtLoad will register it
            // at next login.
            OsWillRun::Yes
        } else {
            OsWillRun::No
        }
    }

    fn prepare_binary(&self, binary: &Path) -> Result<()> {
        // De-quarantine (harmless if the attribute is absent)...
        let _ = self.runner.run(
            "xattr",
            &["-d", "com.apple.quarantine", &binary.display().to_string()],
        );
        // ...then PROVE the binary executes before any definition points at
        // it. A Gatekeeper kill here is an honest install failure with a
        // foreground fallback, not a launchd crash loop (C12).
        let probe = self
            .runner
            .run(&binary.display().to_string(), &["gateway", "service-probe"])?;
        if !probe.ok() || !probe.stdout.contains(super::PROBE_MARKER) {
            return Err(CoreError::InvalidInput(format!(
                "the installed gateway binary did not pass its execution probe \
                 (status {}). On an unsigned build this usually means Gatekeeper \
                 blocked it; run the gateway in the foreground instead \
                 (`tethra gateway serve`) or allow the binary in System Settings \
                 → Privacy & Security.",
                probe.status
            )));
        }
        Ok(())
    }
}
