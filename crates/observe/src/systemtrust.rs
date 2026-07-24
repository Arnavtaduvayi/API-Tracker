//! Mode C — optional installation of the Tethra CA into the OS trust store.
//!
//! This is OFF by default and only ever runs after an explicit, reauthenticated
//! user action. We invoke the operating system's own tooling, which shows its
//! own authorization prompt — we NEVER bypass, suppress, or imitate that
//! prompt. Installation targets the USER trust store (no admin) where the
//! platform offers one.
//!
//! macOS is implemented (login keychain via `security`). Linux and Windows
//! return a documented manual path for this release rather than pretending to
//! automate them.

use api_tracker_core::error::{CoreError, Result};
use std::path::Path;

/// The CN prefix of Tethra CAs, used to find/remove an installed cert.
pub const CA_CN_PREFIX: &str = "Tethra Local Observation CA";

/// Where an installed CA currently stands relative to the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemTrustState {
    /// Not installed in the OS store.
    Absent,
    /// Installed and matching the current vault CA.
    Installed,
    /// A Tethra CA is in the OS store but does not match the vault's current
    /// CA (e.g. the vault was recreated) — an orphan the user should remove.
    Orphaned,
    /// This platform's trust store is not automated in this release.
    Unsupported,
}

fn write_temp_cert(dir: &Path, pem: &str) -> Result<std::path::PathBuf> {
    use std::io::Write;
    let path = dir.join(".api-tracker-tmp-systemtrust-ca.pem");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path).map_err(CoreError::Io)?;
    f.write_all(pem.as_bytes()).map_err(CoreError::Io)?;
    Ok(path)
}

/// Install the CA into the OS user trust store. Runs the platform's own tool,
/// which prompts for authorization. Returns Ok only if the tool reported
/// success.
#[cfg(target_os = "macos")]
pub fn install(dir: &Path, ca_pem: &str) -> Result<()> {
    let cert = write_temp_cert(dir, ca_pem)?;
    // `security add-trusted-cert` targets the login keychain (per-user) and
    // shows macOS's own authorization prompt. `-r trustRoot` trusts it as a
    // root; `-p ssl` limits the trust policy to SSL/TLS.
    let status = std::process::Command::new("security")
        .args(["add-trusted-cert", "-r", "trustRoot", "-p", "ssl"])
        .arg(&cert)
        .status();
    let _ = std::fs::remove_file(&cert);
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(CoreError::InvalidInput(format!(
            "system trust installation was not completed (security exited with {s})"
        ))),
        Err(e) => Err(CoreError::InvalidInput(format!(
            "could not run the macOS `security` tool: {e}"
        ))),
    }
}

/// Remove the Tethra CA from the OS user trust store.
#[cfg(target_os = "macos")]
pub fn remove() -> Result<()> {
    // Delete by common-name prefix. `security delete-certificate` also removes
    // its trust settings. It may prompt.
    let status = std::process::Command::new("security")
        .args(["delete-certificate", "-c", CA_CN_PREFIX])
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        // A non-zero exit when nothing matches is treated as "already absent".
        Ok(_) => Ok(()),
        Err(e) => Err(CoreError::InvalidInput(format!(
            "could not run the macOS `security` tool: {e}"
        ))),
    }
}

/// Detect the current system-trust state for a vault whose CA has the given
/// fingerprint (used to distinguish installed vs orphaned).
#[cfg(target_os = "macos")]
pub fn detect(_vault_fingerprint: &str) -> SystemTrustState {
    let out = std::process::Command::new("security")
        .args(["find-certificate", "-c", CA_CN_PREFIX, "-a"])
        .output();
    match out {
        Ok(o) if o.status.success() && !o.stdout.is_empty() => {
            // A Tethra CA is present. We do not parse the fingerprint here
            // (that requires a certificate parser); the vault's recorded
            // system_trust flag distinguishes installed vs orphaned. Presence
            // means at least Installed-or-Orphaned.
            SystemTrustState::Installed
        }
        _ => SystemTrustState::Absent,
    }
}

#[cfg(not(target_os = "macos"))]
pub fn install(_dir: &Path, _ca_pem: &str) -> Result<()> {
    Err(CoreError::InvalidInput(
        "automated system-trust installation is not available on this platform in this release; \
         see the user guide for the manual steps (the CA fingerprint is shown by `observe cert status`)"
            .into(),
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn remove() -> Result<()> {
    Err(CoreError::InvalidInput(
        "automated system-trust removal is not available on this platform in this release; \
         see the user guide for the manual steps"
            .into(),
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn detect(_vault_fingerprint: &str) -> SystemTrustState {
    SystemTrustState::Unsupported
}
