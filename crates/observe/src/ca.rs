//! The local certificate authority.
//!
//! One CA per vault: a P-256 ECDSA self-signed certificate whose private key is
//! stored ONLY as vault-key ciphertext (the encryption happens in the core
//! vault layer; this module only ever holds the decrypted key in memory for the
//! life of a session). Per-hostname leaf certificates are minted on demand,
//! short-lived, cached in a bounded LRU, and cleared on shutdown/lock.
//!
//! To sign leaves for an *existing* CA without pulling in an X.509 parser, the
//! CA [`Issuer`] is reconstructed from deterministic parameters (a stable
//! distinguished name derived from the vault id, fixed key-usage, default key
//! identifier method) plus the stored key. Because the reconstructed issuer
//! uses the same distinguished name and the same key as the stored CA
//! certificate, leaves it signs chain correctly to that certificate.

use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::secret::SecretBytes;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

/// CA validity: three years.
const CA_VALIDITY_DAYS: i64 = 365 * 3;
/// Leaf validity: 24 hours (short-lived; regenerated as needed).
const LEAF_VALIDITY_HOURS: i64 = 24;
/// Clock-skew allowance for `not_before`.
const SKEW: Duration = Duration::minutes(5);
/// Bounded leaf-certificate cache size.
const LEAF_CACHE_MAX: usize = 256;

fn err(context: &'static str) -> CoreError {
    CoreError::Crypto { context }
}

/// A freshly generated CA, ready to be persisted by the vault layer. `key_der`
/// is the PKCS#8 private key (to be encrypted under the vault key); it is held
/// in a zeroizing buffer.
pub struct GeneratedCa {
    pub cert_pem: String,
    pub cert_der: Vec<u8>,
    pub key_der: SecretBytes,
    pub fingerprint_sha256: String,
    pub serial_hex: String,
    pub not_after: String,
}

/// The stable distinguished name for a vault's CA. Deterministic in `vault_id`
/// so the issuer can be reconstructed to match the stored certificate.
fn ca_distinguished_name(vault_id: &str) -> DistinguishedName {
    let prefix: String = vault_id.chars().take(8).collect();
    let cn = format!("Tethra Local Observation CA ({prefix})");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn.as_str());
    dn.push(DnType::OrganizationName, "Tethra");
    dn
}

/// Deterministic CA parameters used both at generation time and when rebuilding
/// the issuer. Serial/validity are irrelevant to the issuer role (they only
/// matter for the certificate itself), so they are set at generation time only.
fn ca_params(vault_id: &str) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|_| err("ca params"))?;
    params.distinguished_name = ca_distinguished_name(vault_id);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

/// A positive 19-byte serial (top bit cleared, non-zero) from the OS RNG.
fn random_serial_bytes() -> Vec<u8> {
    let mut bytes = api_tracker_core::crypto::random_bytes(19);
    bytes[0] &= 0x7f;
    if bytes.iter().all(|b| *b == 0) {
        bytes[0] = 1;
    }
    bytes
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fingerprint(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Generate a brand-new CA for `vault_id`.
pub fn generate_ca(vault_id: &str) -> Result<GeneratedCa> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| err("ca keygen"))?;
    let mut params = ca_params(vault_id)?;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - SKEW;
    params.not_after = now + Duration::days(CA_VALIDITY_DAYS);
    let serial_bytes = random_serial_bytes();
    let serial_hex = hex_lower(&serial_bytes);
    params.serial_number = Some(SerialNumber::from(serial_bytes));

    let cert = params.self_signed(&key).map_err(|_| err("ca self-sign"))?;
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let fingerprint_sha256 = fingerprint(&cert_der);
    let not_after = (now + Duration::days(CA_VALIDITY_DAYS))
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| err("ca time format"))?;

    Ok(GeneratedCa {
        cert_pem,
        cert_der,
        key_der: SecretBytes::new(key.serialize_der()),
        fingerprint_sha256,
        serial_hex,
        not_after,
    })
}

struct CacheInner {
    /// Most-recently-used at the back; bounded to `LEAF_CACHE_MAX`.
    order: VecDeque<String>,
    entries: std::collections::HashMap<String, Arc<CertifiedKey>>,
}

/// A loaded certificate authority able to mint leaf certificates for the
/// current session. Reconstructs the CA issuer from the stored key; the CA
/// certificate PEM is what the monitored child trusts.
pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    pub ca_cert_pem: String,
    pub fingerprint_sha256: String,
    cache: Mutex<CacheInner>,
}

impl CertAuthority {
    /// Reconstitute a CA from its stored certificate PEM and decrypted PKCS#8
    /// key. Fails closed if the key does not parse.
    pub fn load(
        vault_id: &str,
        ca_cert_pem: &str,
        ca_key_der: &SecretBytes,
        fingerprint_sha256: &str,
    ) -> Result<Self> {
        let key = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(ca_key_der.expose()),
            &PKCS_ECDSA_P256_SHA256,
        )
        .map_err(|_| err("ca key load"))?;
        let params = ca_params(vault_id)?;
        let issuer = Issuer::new(params, key);
        Ok(Self {
            issuer,
            ca_cert_pem: ca_cert_pem.to_string(),
            fingerprint_sha256: fingerprint_sha256.to_string(),
            cache: Mutex::new(CacheInner {
                order: VecDeque::new(),
                entries: std::collections::HashMap::new(),
            }),
        })
    }

    /// Get (or mint and cache) a rustls `CertifiedKey` for `host`.
    pub fn certified_key_for(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let host = host.trim().to_ascii_lowercase();
        {
            let mut cache = self.cache.lock().expect("leaf cache poisoned");
            if let Some(ck) = cache.entries.get(&host).cloned() {
                // move-to-back (most recently used)
                if let Some(pos) = cache.order.iter().position(|h| h == &host) {
                    cache.order.remove(pos);
                }
                cache.order.push_back(host);
                return Ok(ck);
            }
        }
        let ck = Arc::new(self.mint(&host)?);
        let mut cache = self.cache.lock().expect("leaf cache poisoned");
        cache.entries.insert(host.clone(), ck.clone());
        cache.order.push_back(host);
        while cache.order.len() > LEAF_CACHE_MAX {
            if let Some(evict) = cache.order.pop_front() {
                cache.entries.remove(&evict);
            }
        }
        Ok(ck)
    }

    fn mint(&self, host: &str) -> Result<CertifiedKey> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| err("leaf keygen"))?;
        // `new` maps each string to an IpAddress SAN if it parses as an IP,
        // else a DnsName SAN — exactly the behaviour we want for the SNI host.
        let mut params =
            CertificateParams::new(vec![host.to_string()]).map_err(|_| err("leaf params"))?;
        params.is_ca = IsCa::NoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - SKEW;
        params.not_after = now + Duration::hours(LEAF_VALIDITY_HOURS);
        params.serial_number = Some(SerialNumber::from(random_serial_bytes()));

        let leaf = params
            .signed_by(&key, &self.issuer)
            .map_err(|_| err("leaf sign"))?;
        let cert_der: CertificateDer<'static> = leaf.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key_der)
            .map_err(|_| err("leaf signing key"))?;
        Ok(CertifiedKey::new(vec![cert_der], signing_key))
    }

    /// Clear the leaf cache (on lock / shutdown). Dropping the `CertifiedKey`s
    /// drops their signing keys.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().expect("leaf cache poisoned");
        cache.entries.clear();
        cache.order.clear();
    }

    pub fn cache_len(&self) -> usize {
        self.cache.lock().expect("leaf cache poisoned").entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_ca_with_fingerprint_and_pem() {
        let ca = generate_ca("vault-abcdef123456").unwrap();
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!ca.cert_der.is_empty());
        assert_eq!(ca.fingerprint_sha256.matches(':').count(), 31, "sha256 = 32 bytes");
        assert!(!ca.key_der.is_empty());
        // The PEM must never contain the private key.
        assert!(!ca.cert_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn reconstituted_ca_mints_leaves_that_carry_the_hostname() {
        let ca = generate_ca("vault-abcdef123456").unwrap();
        let authority =
            CertAuthority::load("vault-abcdef123456", &ca.cert_pem, &ca.key_der, &ca.fingerprint_sha256)
                .unwrap();
        let ck1 = authority.certified_key_for("api.openai.com").unwrap();
        assert!(!ck1.cert.is_empty());
        // cache hit returns the same Arc
        let ck2 = authority.certified_key_for("API.OpenAI.com").unwrap();
        assert!(Arc::ptr_eq(&ck1, &ck2));
        assert_eq!(authority.cache_len(), 1);

        // an IP host is accepted (IpAddress SAN)
        authority.certified_key_for("93.184.216.34").unwrap();
        assert_eq!(authority.cache_len(), 2);

        authority.clear_cache();
        assert_eq!(authority.cache_len(), 0);
    }

    #[test]
    fn cache_is_bounded() {
        let ca = generate_ca("vault-bound00001").unwrap();
        let authority =
            CertAuthority::load("vault-bound00001", &ca.cert_pem, &ca.key_der, &ca.fingerprint_sha256)
                .unwrap();
        for i in 0..(super::LEAF_CACHE_MAX + 20) {
            authority.certified_key_for(&format!("h{i}.example.test")).unwrap();
        }
        assert_eq!(authority.cache_len(), super::LEAF_CACHE_MAX, "cache must be bounded");
    }
}
