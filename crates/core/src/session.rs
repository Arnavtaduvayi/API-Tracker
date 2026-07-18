//! CLI session mechanism (Bitwarden-style split token).
//!
//! `api-tracker unlock` creates a random 32-byte session token, encrypts the
//! vault key (and any unlocked project keys) under it, and writes only the
//! ciphertext to `session.json` (mode 0600). The token itself is printed once
//! for the user to export as `API_TRACKER_SESSION`; it is never written to
//! disk. Neither the file nor the token alone is sufficient to unlock
//! anything.
//!
//! The session expires after the vault's configured auto-lock period of
//! inactivity (sliding window, refreshed on each use). `api-tracker lock`
//! deletes the file. Limitations are documented in THREAT_MODEL.md: an
//! attacker who can read both the session file *and* the process environment
//! of the user's shell can reconstruct the vault key while a session is
//! active.

use crate::clock;
use crate::crypto::{self, aad};
use crate::error::{CoreError, Result};
use crate::secret::SecretBytes;
use crate::vault::VaultPaths;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroize;

/// Decrypted key material carried by a session.
pub struct SessionKeys {
    pub vault_key: SecretBytes,
    pub project_keys: HashMap<String, SecretBytes>,
}

/// The random per-session secret handed to the user (env var), never stored.
pub struct SessionToken(SecretBytes);

impl SessionToken {
    pub fn generate() -> Self {
        Self(crypto::new_key())
    }

    pub fn encode(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0.expose())
    }

    pub fn decode(encoded: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|_| CoreError::SessionInvalid)?;
        if bytes.len() != crypto::KEY_LEN {
            return Err(CoreError::SessionInvalid);
        }
        Ok(Self(SecretBytes::new(bytes)))
    }

    fn key(&self) -> &SecretBytes {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
struct SessionFile {
    session_id: String,
    created_at: String,
    /// None = auto-lock disabled (no expiry).
    expires_at: Option<String>,
    ttl_minutes: u32,
    payload_b64: String,
}

#[derive(Serialize, Deserialize)]
struct SessionPayload {
    vault_key_hex: String,
    project_keys_hex: HashMap<String, String>,
}

impl Drop for SessionPayload {
    fn drop(&mut self) {
        self.vault_key_hex.zeroize();
        for value in self.project_keys_hex.values_mut() {
            value.zeroize();
        }
    }
}

fn expiry_from_now(ttl_minutes: u32) -> Option<String> {
    if ttl_minutes == 0 {
        None
    } else {
        Some(clock::to_rfc3339(
            clock::now() + time::Duration::minutes(i64::from(ttl_minutes)),
        ))
    }
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}

/// Write the encrypted session file.
pub fn save(
    paths: &VaultPaths,
    token: &SessionToken,
    keys: &SessionKeys,
    ttl_minutes: u32,
) -> Result<()> {
    let session_id = Uuid::new_v4().to_string();
    let payload = SessionPayload {
        vault_key_hex: hex::encode(keys.vault_key.expose()),
        project_keys_hex: keys
            .project_keys
            .iter()
            .map(|(id, key)| (id.clone(), hex::encode(key.expose())))
            .collect(),
    };
    let mut payload_json = serde_json::to_vec(&payload)?;
    let envelope = crypto::encrypt(token.key(), &aad::session(&session_id), &payload_json);
    payload_json.zeroize();
    let envelope = envelope?;
    let file = SessionFile {
        session_id,
        created_at: clock::now_rfc3339(),
        expires_at: expiry_from_now(ttl_minutes),
        ttl_minutes,
        payload_b64: base64::engine::general_purpose::STANDARD.encode(envelope),
    };
    write_private(&paths.session_path(), &serde_json::to_string_pretty(&file)?)?;
    Ok(())
}

/// Load session keys; refreshes the sliding expiry on success. Expired
/// sessions are deleted.
pub fn load_and_refresh(paths: &VaultPaths, token: &SessionToken) -> Result<SessionKeys> {
    let path = paths.session_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CoreError::SessionMissing);
        }
        Err(e) => return Err(e.into()),
    };
    let mut file: SessionFile =
        serde_json::from_str(&raw).map_err(|_| CoreError::SessionInvalid)?;
    if let Some(expires_at) = &file.expires_at {
        let expires = clock::parse_rfc3339(expires_at).map_err(|_| CoreError::SessionInvalid)?;
        if clock::now() >= expires {
            let _removed = std::fs::remove_file(&path);
            return Err(CoreError::SessionExpired);
        }
    }
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(&file.payload_b64)
        .map_err(|_| CoreError::SessionInvalid)?;
    let plaintext = crypto::decrypt(
        token.key(),
        &aad::session(&file.session_id),
        &envelope,
        "session",
    )
    .map_err(|_| CoreError::SessionInvalid)?;
    let payload: SessionPayload =
        serde_json::from_slice(plaintext.expose()).map_err(|_| CoreError::SessionInvalid)?;
    let vault_key = SecretBytes::new(
        hex::decode(&payload.vault_key_hex).map_err(|_| CoreError::SessionInvalid)?,
    );
    let mut project_keys = HashMap::new();
    for (id, key_hex) in &payload.project_keys_hex {
        project_keys.insert(
            id.clone(),
            SecretBytes::new(hex::decode(key_hex).map_err(|_| CoreError::SessionInvalid)?),
        );
    }
    // Sliding expiry refresh.
    file.expires_at = expiry_from_now(file.ttl_minutes);
    write_private(&path, &serde_json::to_string_pretty(&file)?)?;
    Ok(SessionKeys {
        vault_key,
        project_keys,
    })
}

/// Delete the session file. Returns whether one existed.
pub fn destroy(paths: &VaultPaths) -> Result<bool> {
    match std::fs::remove_file(paths.session_path()) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Non-secret session metadata, for `doctor`.
#[derive(Debug, Clone, Serialize)]
pub struct SessionStatus {
    pub created_at: String,
    pub expires_at: Option<String>,
}

pub fn status(paths: &VaultPaths) -> Result<Option<SessionStatus>> {
    let path = paths.session_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let file: SessionFile = serde_json::from_str(&raw).map_err(|_| CoreError::SessionInvalid)?;
    Ok(Some(SessionStatus {
        created_at: file.created_at,
        expires_at: file.expires_at,
    }))
}
