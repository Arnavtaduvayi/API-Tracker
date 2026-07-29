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

use super::{
    CommandRunner, Definition, DefinitionState, OsWillRun, RegistrationState, ServiceManager,
};

/// The label used before per-installation namespacing. Kept ONLY so
/// migration can recognise and take over an agent this machine already has
/// (see [`LaunchAgent::reclaim_legacy`]); nothing new is ever registered
/// under it.
///
/// It was a fixed global constant, which is precisely the defect: the plist
/// PATH follows `$HOME`, but `bootout gui/<uid>/<label>` addresses the real
/// session domain regardless of `HOME`, so a second environment installing
/// its "own" service booted out the first one's running gateway (ZFT-014).
pub const LEGACY_LABEL: &str = "dev.api-tracker.gateway";

/// The label for one installation: the preserved `dev.api-tracker.*`
/// identifier family (rebrand policy) plus the installation id, so each
/// data directory owns a distinct job in `gui/<uid>`.
pub fn label_for(installation_id: &str) -> String {
    format!("{LEGACY_LABEL}.{installation_id}")
}

pub struct LaunchAgent {
    pub data_dir: PathBuf,
    /// Namespace for the label and plist file name; see
    /// [`super::installation_id`].
    pub installation_id: String,
    /// `~/Library/LaunchAgents` on a real host; a temp dir in tests.
    pub launch_agents_dir: PathBuf,
    /// The user's numeric uid for the `gui/<uid>` domain target.
    pub uid: String,
    pub runner: Arc<dyn CommandRunner>,
}

impl LaunchAgent {
    /// Derives the installation id from `data_dir` — always construct
    /// through here (or [`LaunchAgent::for_host`]) so the id can never
    /// disagree with the directory whose service it names.
    pub fn new(
        data_dir: &Path,
        launch_agents_dir: PathBuf,
        uid: String,
        runner: Arc<dyn CommandRunner>,
    ) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            installation_id: super::installation_id(data_dir),
            launch_agents_dir,
            uid,
            runner,
        }
    }

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
        let uid = uid_out.stdout.trim().to_string();
        Ok(Self::new(
            data_dir,
            PathBuf::from(home).join("Library").join("LaunchAgents"),
            uid,
            runner,
        ))
    }

    /// This installation's launchd label.
    pub fn label(&self) -> String {
        label_for(&self.installation_id)
    }

    fn domain_target(&self) -> String {
        format!("gui/{}", self.uid)
    }

    fn service_target(&self) -> String {
        format!("gui/{}/{}", self.uid, self.label())
    }

    fn plist_path(&self, label: &str) -> PathBuf {
        self.launch_agents_dir.join(format!("{label}.plist"))
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
            label = self.label(),
            bin = xml_escape(&binary.display().to_string()),
            dir = xml_escape(&self.data_dir.display().to_string()),
            log = xml_escape(&log.display().to_string()),
        )
    }
}

/// Whether a `launchctl bootout` left the label unloaded. A job that was
/// not loaded in the first place is success for every caller here.
fn bootout_settled(out: &super::RunOutput) -> bool {
    out.ok()
        || out.stderr.contains("No such process")
        || out.stderr.contains("not find")
        || out.status == 3
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

/// Read and parse a plist THIS module wrote, wherever it sits. Shared by
/// the namespaced read and the legacy-migration probe.
///
/// Three states, not two: an absent plist and one we cannot read answered
/// the same `None`, and `ensure_ours` acted on that `None` as "empty slot"
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
    let args = parse_program_arguments(&content);
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

impl ServiceManager for LaunchAgent {
    fn platform(&self) -> &'static str {
        "macos-launch-agent"
    }

    fn owned_data_dir(&self) -> &Path {
        &self.data_dir
    }

    fn installation_id(&self) -> &str {
        &self.installation_id
    }

    fn service_name(&self) -> String {
        self.label()
    }

    fn reclaim_legacy(&self) -> Result<Option<String>> {
        let path = self.plist_path(LEGACY_LABEL);
        // Unreadable or unparseable means we cannot PROVE it is ours, which
        // is the same answer as "someone else's": leave it.
        let DefinitionState::Present(def) = definition_at(&path) else {
            return Ok(None);
        };
        if !super::same_data_dir(&def.data_dir, &self.data_dir) {
            return Ok(None);
        }
        // Ours, under the old global label. Unload it before the namespaced
        // job claims the port, then delete the plist so login does not start
        // two gateways against one vault.
        let target = format!("gui/{}/{LEGACY_LABEL}", self.uid);
        let out = self.runner.run("launchctl", &["bootout", &target])?;
        if !bootout_settled(&out) {
            return Err(CoreError::InvalidInput(format!(
                "could not unload the legacy LaunchAgent {LEGACY_LABEL} (status {}): {}",
                out.status,
                out.stderr.trim()
            )));
        }
        std::fs::remove_file(&path).map_err(CoreError::Io)?;
        Ok(Some(LEGACY_LABEL.to_string()))
    }

    fn definition_path(&self) -> PathBuf {
        self.plist_path(&self.label())
    }

    fn write_definition(&self, binary: &Path) -> Result<()> {
        std::fs::create_dir_all(&self.launch_agents_dir).map_err(CoreError::Io)?;
        // Temp + rename, never truncate-in-place: launchd loads every plist
        // in this directory at login, and a reader that catches a partial
        // write sees `Unparseable`, which every later verb then refuses
        // (NEW-02). See `super::atomic_write_definition`.
        super::atomic_write_definition(&self.definition_path(), &self.render_plist(binary))
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
        Ok(())
    }

    fn register(&self) -> Result<()> {
        // Bootstrapping puts a definition into the LIVE gui/<uid> domain.
        // Doing that to a plist we cannot prove is ours would hand another
        // installation's gateway a login slot in this session.
        self.ensure_ours("register")?;
        let plist = self.definition_path().display().to_string();
        let out = self
            .runner
            .run("launchctl", &["bootstrap", &self.domain_target(), &plist])?;
        if out.ok() {
            return Ok(());
        }
        // Already bootstrapped: launchd is holding the PREVIOUS job spec,
        // including the previous binary path — and install/repair has just
        // rewritten the plist and is about to prune that binary. `bootstrap`
        // does not re-read a loaded job and `kickstart` (without -k) does not
        // restart a running one, so the only way to make the new definition
        // take effect is to bootout first and bootstrap again. The bootout
        // goes through `unregister`, which proves the plist we are about to
        // unload is ours — an "already bootstrapped" answer is not evidence
        // that the loaded job belongs to this data directory.
        if out.stderr.contains("already bootstrapped") || out.status == 5 {
            self.unregister()?;
            let retry = self
                .runner
                .run("launchctl", &["bootstrap", &self.domain_target(), &plist])?;
            if !retry.ok() {
                return Err(CoreError::InvalidInput(format!(
                    "launchctl bootstrap failed after bootout (status {}): {}",
                    retry.status,
                    retry.stderr.trim()
                )));
            }
            return Ok(());
        }
        Err(CoreError::InvalidInput(format!(
            "launchctl bootstrap failed (status {}): {}",
            out.status,
            out.stderr.trim()
        )))
    }

    fn unregister(&self) -> Result<()> {
        // The bootout below removes a job from the LIVE session domain, so
        // it must never run against a label whose plist points somewhere
        // else — this is the exact call that took down another
        // installation's gateway (ZFT-014).
        self.ensure_ours("unregister the service")?;
        let out = self
            .runner
            .run("launchctl", &["bootout", &self.service_target()])?;
        if !bootout_settled(&out) {
            return Err(CoreError::InvalidInput(format!(
                "launchctl bootout failed (status {}): {}",
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn start(&self) -> Result<()> {
        // Starting a foreign definition launches another installation's
        // gateway against another vault. `start` is not destructive, but it
        // is still "reconfigure another environment's service".
        self.ensure_ours("start")?;
        let out = self
            .runner
            .run("launchctl", &["kickstart", &self.service_target()])?;
        if out.ok() {
            return Ok(());
        }
        // `stop` is a bootout, which UNLOADS the label until next login, so
        // after `tethra gateway stop` there is nothing for kickstart to find.
        // Bootstrap it back and retry — otherwise `stop` then `start` fails
        // on macOS until the user logs out and in again.
        self.register()?;
        let retry = self
            .runner
            .run("launchctl", &["kickstart", &self.service_target()])?;
        if !retry.ok() {
            return Err(CoreError::InvalidInput(format!(
                "launchctl kickstart failed (status {}): {}",
                retry.status,
                retry.stderr.trim()
            )));
        }
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        // bootout stops AND unloads until next login; for a plain stop we
        // bootout then leave the plist in place — RunAtLoad re-registers at
        // next login, and `start`/`restart` re-bootstraps explicitly.
        // Proven under this verb so the refusal names what the user asked
        // for, not the internal unregister.
        self.ensure_ours("stop the service")?;
        self.unregister()
    }

    fn restart(&self) -> Result<()> {
        // kickstart -k KILLS the running instance, so it needs the same
        // ownership proof as a stop.
        self.ensure_ours("restart the service")?;
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
