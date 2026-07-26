//! TLS configuration for the interception proxy.
//!
//! Two configs matter:
//! - **Upstream (client)**: how the proxy connects to the *real* provider. It
//!   verifies the provider's certificate against the bundled Mozilla root
//!   store (`webpki-roots`) with full, default verification. There is NO
//!   permissive/"accept invalid" verifier anywhere in this crate — a
//!   source-level test (`tests/no_insecure_verifier.rs`) enforces that.
//! - **Downstream (server)**: how the proxy presents itself to the monitored
//!   child, using a leaf certificate minted by the local CA
//!   ([`crate::ca::CertAuthority`]) for the requested host, advertising only
//!   `http/1.1` so we never have to decode HTTP/2.
//!
//! The `ring` crypto provider is passed explicitly (via `builder_with_provider`)
//! so this crate never depends on a process-wide default provider being
//! installed.

use crate::ca::CertAuthority;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring::default_provider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::{Arc, OnceLock};

/// ALPN we advertise on intercepted connections: HTTP/1.1 only.
const ALPN_HTTP11: &[&[u8]] = &[b"http/1.1"];

/// The shared, fully-verifying upstream client config. Built once.
pub fn upstream_client_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Default (full) verification: chain + hostname + validity, against the
        // bundled root store. No `dangerous()` call, ever.
        let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = ALPN_HTTP11.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    })
    .clone()
}

/// Compile-time assurance that this module references the real verifier trait
/// only to *name* it here (for the guard test), never to replace it. This
/// function is intentionally unused at runtime.
#[allow(dead_code)]
fn _verifier_type_is_the_standard_one(_v: &dyn ServerCertVerifier) {}

/// A cert resolver that always returns one pre-minted [`CertifiedKey`] — the
/// leaf for the host this intercepted connection targets.
#[derive(Debug)]
struct FixedResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Build a downstream server config presenting `ck` (the CA-signed leaf for the
/// target host), advertising only HTTP/1.1.
pub fn server_config_for(ck: Arc<CertifiedKey>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedResolver(ck)));
    config.alpn_protocols = ALPN_HTTP11.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// Convenience: the server config for `host`, minting/caching the leaf via the
/// CA.
pub fn server_config_for_host(
    ca: &CertAuthority,
    host: &str,
) -> api_tracker_core::error::Result<Arc<ServerConfig>> {
    let ck = ca.certified_key_for(host)?;
    Ok(server_config_for(ck))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_config_is_shared_and_http11() {
        let a = upstream_client_config();
        let b = upstream_client_config();
        assert!(Arc::ptr_eq(&a, &b), "config is built once");
        assert_eq!(a.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn server_config_advertises_only_http11() {
        let ca = crate::ca::generate_ca("vault-tls00000001").unwrap();
        let authority = crate::ca::CertAuthority::load(
            "vault-tls00000001",
            &ca.cert_pem,
            &ca.key_der,
            &ca.fingerprint_sha256,
        )
        .unwrap();
        let cfg = server_config_for_host(&authority, "api.openai.com").unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
