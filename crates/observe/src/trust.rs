//! Scoped runtime trust: the environment applied to the launched child ONLY.
//!
//! We never modify the parent shell, the system proxy, or the system trust
//! store. For the monitored child we set:
//! - proxy variables pointing at the loopback proxy (with the per-session
//!   token embedded so the client sends `Proxy-Authorization` automatically);
//! - the CA-trust variable each runtime honours, pointing at either the bare
//!   CA (append-semantics: Node's `NODE_EXTRA_CA_CERTS`) or a COMBINED bundle
//!   of the system roots plus the Tethra CA (replace-semantics:
//!   `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, …), so a host the
//!   proxy tunnels opaquely (h2-only) can still be verified against real roots.
//!
//! We NEVER set `NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONHTTPSVERIFY=0`,
//! `GIT_SSL_NO_VERIFY`, or any other verification-disabling variable — a
//! source-level test forbids it.

use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::runtime::model::{ObservationMode, TrustLevel};
use std::path::{Path, PathBuf};

/// Candidate system CA bundle locations, most specific first. The first that
/// exists is concatenated with the Tethra CA to form the combined bundle.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/cert.pem",                    // macOS (OpenSSL), some BSDs
    "/etc/ssl/certs/ca-certificates.crt",   // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",     // RHEL/Fedora
    "/opt/homebrew/etc/openssl@3/cert.pem", // Homebrew (Apple silicon)
    "/usr/local/etc/openssl@3/cert.pem",    // Homebrew (Intel)
];

/// Variables that must NEVER be set (verification-disabling). Present so the
/// guard test and reviewers can see them named in one place.
pub const FORBIDDEN_VARS: &[&str] = &[
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "PYTHONHTTPSVERIFY",
    "GIT_SSL_NO_VERIFY",
    "CURL_INSECURE",
    "SSL_VERIFY",
];

/// The detected runtime and how well scoped trust is expected to work.
#[derive(Debug, Clone)]
pub struct RuntimeAssessment {
    pub runtime: String,
    pub trust_level: TrustLevel,
}

/// Best-effort runtime detection from the launched program name.
pub fn detect_runtime(program: &str) -> RuntimeAssessment {
    let base = Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    let (runtime, trust_level) = match base {
        "node" | "npm" | "npx" | "yarn" | "pnpm" | "bun" | "deno" => {
            ("node", TrustLevel::FullySupported)
        }
        "curl" => ("curl", TrustLevel::FullySupported),
        "python" | "python3" | "pip" | "pip3" | "uv" | "poetry" => {
            ("python", TrustLevel::ProbablySupported)
        }
        "ruby" | "bundle" | "gem" => ("ruby", TrustLevel::ProbablySupported),
        "php" | "composer" => ("php", TrustLevel::ProbablySupported),
        "go" => ("go", TrustLevel::ConnectionOnlyFallback),
        "java" | "gradle" | "mvn" | "mvnw" => ("java", TrustLevel::Unsupported),
        "dotnet" => ("dotnet", TrustLevel::Unsupported),
        _ => ("unknown", TrustLevel::ProbablySupported),
    };
    RuntimeAssessment {
        runtime: runtime.to_string(),
        trust_level,
    }
}

/// Owns the temp trust files and the environment to apply to the child. Deletes
/// the temp files on drop.
pub struct ScopedTrust {
    proxy_url: String,
    ca_file: Option<PathBuf>,
    bundle_file: Option<PathBuf>,
    /// True when the combined bundle actually included system roots (so
    /// opaque-tunnelled hosts can still be verified).
    pub has_system_roots: bool,
}

fn write_0600(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(CoreError::Io)?;
    f.write_all(contents.as_bytes()).map_err(CoreError::Io)?;
    Ok(())
}

impl ScopedTrust {
    /// Prepare scoped trust. `dir` is where the temp files go (the vault data
    /// dir); `token` embeds into the proxy URL. In `Connection` mode only the
    /// proxy variables are prepared (no CA trust).
    pub fn prepare(
        dir: &Path,
        proxy_port: u16,
        token: &str,
        ca_pem: &str,
        mode: ObservationMode,
        infix: &str,
    ) -> Result<Self> {
        let proxy_url = format!("http://tethra:{token}@127.0.0.1:{proxy_port}");
        if mode != ObservationMode::Metadata {
            return Ok(Self {
                proxy_url,
                ca_file: None,
                bundle_file: None,
                has_system_roots: false,
            });
        }

        // Bare CA file for append-semantics runtimes (Node).
        let ca_file = dir.join(format!(".api-tracker-tmp-{infix}-ca.pem"));
        write_0600(&ca_file, ca_pem)?;

        // Combined bundle: system roots ++ Tethra CA, for replace-semantics
        // runtimes. Falls back to the bare CA if no system bundle is found.
        let (combined, has_system_roots) =
            match SYSTEM_BUNDLES.iter().find(|p| Path::new(p).exists()) {
                Some(path) => match std::fs::read_to_string(path) {
                    Ok(system) => (format!("{system}\n{ca_pem}\n"), true),
                    Err(_) => (ca_pem.to_string(), false),
                },
                None => (ca_pem.to_string(), false),
            };
        let bundle_file = dir.join(format!(".api-tracker-tmp-{infix}-bundle.pem"));
        write_0600(&bundle_file, &combined)?;

        Ok(Self {
            proxy_url,
            ca_file: Some(ca_file),
            bundle_file: Some(bundle_file),
            has_system_roots,
        })
    }

    /// The `(name, value)` environment pairs to apply to the child. Existing
    /// `NO_PROXY` is merged; loopback is always excluded from proxying.
    pub fn child_env(&self, existing_no_proxy: Option<&str>) -> Vec<(String, String)> {
        let mut env = Vec::new();
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            env.push((k.to_string(), self.proxy_url.clone()));
        }
        let mut no_proxy = existing_no_proxy.unwrap_or("").to_string();
        for host in ["localhost", "127.0.0.1", "::1"] {
            if !no_proxy.split(',').any(|h| h.trim() == host) {
                if !no_proxy.is_empty() {
                    no_proxy.push(',');
                }
                no_proxy.push_str(host);
            }
        }
        env.push(("NO_PROXY".into(), no_proxy.clone()));
        env.push(("no_proxy".into(), no_proxy));

        if let Some(ca) = &self.ca_file {
            let ca = ca.display().to_string();
            env.push(("NODE_EXTRA_CA_CERTS".into(), ca));
        }
        if let Some(bundle) = &self.bundle_file {
            let b = bundle.display().to_string();
            for k in [
                "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE",
                "SSL_CERT_FILE",
                "AWS_CA_BUNDLE",
                "GIT_SSL_CAINFO",
            ] {
                env.push((k.to_string(), b.clone()));
            }
        }
        env
    }

    /// Apply the scoped environment to a command (child only).
    pub fn apply(&self, cmd: &mut std::process::Command) {
        let existing = std::env::var("NO_PROXY").ok();
        for (k, v) in self.child_env(existing.as_deref()) {
            cmd.env(k, v);
        }
    }
}

impl Drop for ScopedTrust {
    fn drop(&mut self) {
        if let Some(p) = &self.ca_file {
            let _ = std::fs::remove_file(p);
        }
        if let Some(p) = &self.bundle_file {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_runtimes() {
        assert_eq!(detect_runtime("/usr/local/bin/node").runtime, "node");
        assert_eq!(
            detect_runtime("node").trust_level,
            TrustLevel::FullySupported
        );
        assert_eq!(
            detect_runtime("curl").trust_level,
            TrustLevel::FullySupported
        );
        assert_eq!(detect_runtime("python3").runtime, "python");
        assert_eq!(detect_runtime("java").trust_level, TrustLevel::Unsupported);
        assert_eq!(
            detect_runtime("go").trust_level,
            TrustLevel::ConnectionOnlyFallback
        );
    }

    #[test]
    fn scoped_env_sets_proxy_and_trust_never_disables_verification() {
        let dir = std::env::temp_dir();
        let infix = "test-scoped-0001";
        let trust = ScopedTrust::prepare(
            &dir,
            9999,
            "TOKEN123",
            "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
            ObservationMode::Metadata,
            infix,
        )
        .unwrap();
        let env = trust.child_env(Some("example.com"));
        let map: std::collections::HashMap<_, _> = env.iter().cloned().collect();
        assert_eq!(
            map.get("HTTPS_PROXY").unwrap(),
            "http://tethra:TOKEN123@127.0.0.1:9999"
        );
        assert!(map.get("NO_PROXY").unwrap().contains("127.0.0.1"));
        assert!(
            map.get("NO_PROXY").unwrap().contains("example.com"),
            "existing NO_PROXY preserved"
        );
        assert!(map.contains_key("NODE_EXTRA_CA_CERTS"));
        assert!(map.contains_key("REQUESTS_CA_BUNDLE"));
        assert!(map.contains_key("CURL_CA_BUNDLE"));
        // NEVER a verification-disabling variable
        for forbidden in FORBIDDEN_VARS {
            assert!(!map.contains_key(*forbidden), "must never set {forbidden}");
        }
        drop(trust); // temp files cleaned up
    }

    #[test]
    fn connection_mode_sets_no_ca_trust() {
        let dir = std::env::temp_dir();
        let trust = ScopedTrust::prepare(
            &dir,
            9999,
            "T",
            "ca",
            ObservationMode::Connection,
            "test-conn-0001",
        )
        .unwrap();
        let map: std::collections::HashMap<_, _> = trust.child_env(None).into_iter().collect();
        assert!(map.contains_key("HTTPS_PROXY"));
        assert!(
            !map.contains_key("NODE_EXTRA_CA_CERTS"),
            "connection mode does not decrypt"
        );
    }
}
