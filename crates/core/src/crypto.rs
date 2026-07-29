//! Cryptographic primitives for the vault.
//!
//! Design (see docs/decisions/0002-cryptography.md):
//! - Argon2id (memory-hard) stretches passwords into key-encryption keys.
//! - XChaCha20-Poly1305 provides authenticated encryption with a random
//!   24-byte nonce per envelope.
//! - Every envelope is bound to contextual associated data (AAD) naming the
//!   vault/project/credential it belongs to, so ciphertext cannot be swapped
//!   between rows without detection.
//! - Envelopes carry a version byte so algorithms can be migrated later.
//! - All randomness comes from the operating system RNG (`getrandom`).
//!
//! No custom cryptographic constructions: this module only composes the
//! audited RustCrypto implementations.

use crate::error::{CoreError, Result};
use crate::secret::{SecretBytes, SecretString};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

/// Version byte written at the start of every envelope, and the version
/// namespace used in AAD strings. Bump when algorithms change.
pub const CRYPTO_VERSION: u8 = 1;
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// Argon2id parameters, persisted next to every password-derived wrap so old
/// vaults keep unlocking after defaults change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Current recommended parameters: Argon2id, 64 MiB, 3 iterations,
    /// 1 lane (OWASP-recommended range for interactive logins).
    ///
    /// Debug builds only: setting `TETHRA_INSECURE_FAST_KDF=1` (or the
    /// legacy `API_TRACKER_INSECURE_FAST_KDF=1`) switches to deliberately
    /// weak parameters so the automated test suite stays fast. Release
    /// builds ignore the variable entirely. Vaults always store the
    /// parameters they were created with and unlock with those.
    pub fn recommended() -> Self {
        if cfg!(debug_assertions) && crate::envcompat::is_set("INSECURE_FAST_KDF") {
            return Self {
                algorithm: "argon2id".to_owned(),
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            };
        }
        Self {
            algorithm: "argon2id".to_owned(),
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Fill a fresh buffer from the OS cryptographic RNG.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("operating system RNG is unavailable");
    buf
}

pub fn new_key() -> SecretBytes {
    SecretBytes::new(random_bytes(KEY_LEN))
}

pub fn new_salt() -> Vec<u8> {
    random_bytes(SALT_LEN)
}

/// Derive a 32-byte key from a password with Argon2id.
pub fn derive_key(password: &SecretString, salt: &[u8], params: &KdfParams) -> Result<SecretBytes> {
    if params.algorithm != "argon2id" {
        return Err(CoreError::Kdf);
    }
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| CoreError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = vec![0u8; KEY_LEN];
    argon
        .hash_password_into(password.expose().as_bytes(), salt, &mut out)
        .map_err(|_| CoreError::Kdf)?;
    Ok(SecretBytes::new(out))
}

/// Encrypt `plaintext` under `key`, bound to `aad`.
/// Envelope layout: `[version:1][nonce:24][ciphertext+tag]`.
pub fn encrypt(key: &SecretBytes, aad: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CoreError::Crypto {
            context: "invalid key length",
        })?;
    let nonce_bytes = random_bytes(NONCE_LEN);
    let nonce = XNonce::try_from(nonce_bytes.as_slice()).map_err(|_| CoreError::Crypto {
        context: "invalid nonce length",
    })?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CoreError::Crypto {
            context: "encryption",
        })?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(CRYPTO_VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt an envelope produced by [`encrypt`]. Fails if the key is wrong,
/// the data was modified, or the AAD does not match.
pub fn decrypt(
    key: &SecretBytes,
    aad: &str,
    envelope: &[u8],
    context: &'static str,
) -> Result<SecretBytes> {
    if envelope.len() < 1 + NONCE_LEN + TAG_LEN {
        return Err(CoreError::Crypto { context });
    }
    if envelope[0] != CRYPTO_VERSION {
        return Err(CoreError::Crypto { context });
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| CoreError::Crypto { context })?;
    let nonce =
        XNonce::try_from(&envelope[1..1 + NONCE_LEN]).map_err(|_| CoreError::Crypto { context })?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &envelope[1 + NONCE_LEN..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CoreError::Crypto { context })?;
    Ok(SecretBytes::new(plaintext))
}

/// Associated-data strings. Each binds a ciphertext to its exact place in the
/// data model and to the crypto version.
pub mod aad {
    pub fn vault_key(vault_id: &str) -> String {
        format!("api-tracker:v1:vault-key:{vault_id}")
    }
    pub fn fingerprint_key(vault_id: &str) -> String {
        format!("api-tracker:v1:fingerprint-key:{vault_id}")
    }
    /// The gateway route-MAC key (ADR 0019 D3): a matching/MAC-only key that
    /// authenticates CUSTOM-ORIGIN route rows, so a same-uid `UPDATE` of a
    /// stored custom origin in the plaintext gateway_routes table stops the
    /// route rather than redirecting it, and no destination the user never
    /// approved can be injected. It does not cover built-in routes, whose
    /// `provider_id` selector is unauthenticated, and it is not consulted for
    /// a row whose custom columns have been nulled (SEC-01 / NEW-49 — accepted
    /// exclusion, see docs/gateway/SECURITY.md). Like the fingerprint key it
    /// can never decrypt anything.
    pub fn gateway_mac_key(vault_id: &str) -> String {
        format!("api-tracker:v1:gateway-mac-key:{vault_id}")
    }
    /// The env-restore-record key (ADR 0028): wraps the *prior values* a
    /// link recorded so they can be put back on unlink.
    ///
    /// Unlike the two keys above this one really does decrypt — that is its
    /// whole job — so it is held only by a process with an unlocked vault
    /// and is never pushed over the gateway control socket.
    pub fn env_restore_key(vault_id: &str) -> String {
        format!("api-tracker:v1:env-restore-key:{vault_id}")
    }
    /// One recorded prior value, bound to the link and the exact file and
    /// variable it belongs to, so a ciphertext cannot be moved between
    /// variables, files or links and still decrypt.
    pub fn env_restore_value(vault_id: &str, link_slug: &str, path: &str, key: &str) -> String {
        format!("api-tracker:v1:env-restore-value:{vault_id}:{link_slug}:{path}:{key}")
    }
    /// Outer wrap of a project key (under the vault key).
    pub fn project_key(vault_id: &str, project_id: &str) -> String {
        format!("api-tracker:v1:project-key:{vault_id}:{project_id}")
    }
    /// Inner wrap of a password-locked project key (under the project
    /// password KEK).
    pub fn project_key_password(vault_id: &str, project_id: &str) -> String {
        format!("api-tracker:v1:project-key-password:{vault_id}:{project_id}")
    }
    pub fn credential_value(vault_id: &str, project_id: &str, credential_id: &str) -> String {
        format!("api-tracker:v1:credential-value:{vault_id}:{project_id}:{credential_id}")
    }
    pub fn backup(vault_id: &str) -> String {
        format!("api-tracker:v1:backup:{vault_id}")
    }
    /// Format-v2 backups bind the (plaintext-header) format version into the
    /// AAD so a tampered header cannot demote a payload to another parser.
    pub fn backup_v2(vault_id: &str) -> String {
        format!("api-tracker:v1:backup-format2:{vault_id}")
    }
    /// A provider's administrative connection key (vault-level, encrypted
    /// under the vault key; not tied to any project).
    pub fn provider_admin(vault_id: &str, provider: &str) -> String {
        format!("api-tracker:v1:provider-admin:{vault_id}:{provider}")
    }
    pub fn session(session_id: &str) -> String {
        format!("api-tracker:v1:session:{session_id}")
    }
    /// A retained prior credential value (version history), bound to its
    /// version number so rows cannot be swapped between versions.
    pub fn credential_version(
        vault_id: &str,
        project_id: &str,
        credential_id: &str,
        version: i64,
    ) -> String {
        format!(
            "api-tracker:v1:credential-version:{vault_id}:{project_id}:{credential_id}:{version}"
        )
    }
    /// A destination's administrative credential (vault-level, encrypted
    /// under the vault key; not tied to any project).
    pub fn destination_auth(vault_id: &str, destination_id: &str) -> String {
        format!("api-tracker:v1:destination-auth:{vault_id}:{destination_id}")
    }
    /// A notification channel's webhook URL (may embed a user token).
    pub fn notification_channel(vault_id: &str, channel_id: &str) -> String {
        format!("api-tracker:v1:notification-channel:{vault_id}:{channel_id}")
    }
    /// The runtime-observability local CA private key (vault-level; encrypted
    /// under the vault key, never written in plaintext).
    ///
    /// The AAD binds the vault id AND a hash of the CA *certificate* PEM, so the
    /// public `ca_cert_pem` column is cryptographically tied to the encrypted
    /// key. An attacker with DB write access who swaps in a foreign certificate
    /// (to launder their own CA — whose private key they hold — into the OS
    /// trust store via a consented Mode C install) changes this hash, so the key
    /// ciphertext no longer authenticates and every decrypt fails CLOSED. The
    /// swapped certificate can therefore never be materialized or installed.
    pub fn observe_ca_key(vault_id: &str, cert_pem: &str) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(cert_pem.as_bytes());
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        format!("api-tracker:v1:observe-ca-key:{vault_id}:{hex}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretBytes {
        new_key()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let k = key();
        let ct = encrypt(&k, "ctx", b"FAKE-TEST-NOT-A-REAL-KEY-000001").unwrap();
        let pt = decrypt(&k, "ctx", &ct, "test").unwrap();
        assert_eq!(pt.expose(), b"FAKE-TEST-NOT-A-REAL-KEY-000001");
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(&key(), "ctx", b"payload").unwrap();
        assert!(matches!(
            decrypt(&key(), "ctx", &ct, "test"),
            Err(CoreError::Crypto { .. })
        ));
    }

    #[test]
    fn corrupted_ciphertext_fails() {
        let k = key();
        let mut ct = encrypt(&k, "ctx", b"payload").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt(&k, "ctx", &ct, "test").is_err());
    }

    #[test]
    fn modified_aad_fails() {
        let k = key();
        let ct = encrypt(&k, "ctx-a", b"payload").unwrap();
        assert!(decrypt(&k, "ctx-b", &ct, "test").is_err());
    }

    #[test]
    fn truncated_envelope_fails() {
        let k = key();
        let ct = encrypt(&k, "ctx", b"payload").unwrap();
        assert!(decrypt(&k, "ctx", &ct[..10], "test").is_err());
        assert!(decrypt(&k, "ctx", &[], "test").is_err());
    }

    #[test]
    fn unknown_version_fails() {
        let k = key();
        let mut ct = encrypt(&k, "ctx", b"payload").unwrap();
        ct[0] = 99;
        assert!(decrypt(&k, "ctx", &ct, "test").is_err());
    }

    #[test]
    fn nonces_are_unique_per_envelope() {
        let k = key();
        let a = encrypt(&k, "ctx", b"payload").unwrap();
        let b = encrypt(&k, "ctx", b"payload").unwrap();
        assert_ne!(a[1..1 + NONCE_LEN], b[1..1 + NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_key_is_deterministic_per_salt() {
        let params = KdfParams {
            algorithm: "argon2id".into(),
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let pw = SecretString::from("test-master-password");
        let salt_a = new_salt();
        let salt_b = new_salt();
        let k1 = derive_key(&pw, &salt_a, &params).unwrap();
        let k2 = derive_key(&pw, &salt_a, &params).unwrap();
        let k3 = derive_key(&pw, &salt_b, &params).unwrap();
        assert!(k1.ct_eq(&k2));
        assert!(!k1.ct_eq(&k3));
    }

    #[test]
    fn unsupported_kdf_algorithm_rejected() {
        let params = KdfParams {
            algorithm: "md5".into(),
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let pw = SecretString::from("pw");
        assert!(matches!(
            derive_key(&pw, &new_salt(), &params),
            Err(CoreError::Kdf)
        ));
    }
}
