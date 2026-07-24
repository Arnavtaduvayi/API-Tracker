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
    /// Project key paired with the BLAKE3 hash of the wrapped-key blob it
    /// was unwrapped from (the vault checks it for freshness before use).
    pub project_keys: HashMap<String, (SecretBytes, [u8; 32])>,
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

/// A sibling temp path in the same directory as `path` (so a rename to `path`
/// is atomic — same filesystem). A random suffix avoids collisions between
/// concurrent writers.
fn temp_sibling(path: &std::path::Path) -> std::path::PathBuf {
    let suffix = hex::encode(crypto::random_bytes(6));
    let mut name = path
        .file_name()
        .map(|f| f.to_os_string())
        .unwrap_or_default();
    name.push(format!(".tmp-{suffix}"));
    path.with_file_name(name)
}

/// Write the session file ATOMICALLY: write a private temp sibling, then rename
/// it over the destination. `std::fs::rename` replaces the target atomically on
/// both POSIX and Windows, so a concurrent reader (e.g. the observed-run lock
/// watch calling [`peek_state`]) never observes a truncated or half-written
/// file — which previously could look like a deleted session and spuriously
/// interrupt an active run.
#[cfg(unix)]
fn write_private(path: &std::path::Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = temp_sibling(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(contents.as_bytes())?;
    let _ = file.sync_all();
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, contents: &str) -> Result<()> {
    let tmp = temp_sibling(path);
    std::fs::write(&tmp, contents)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
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
            .map(|(id, (key, wrap_hash))| {
                // key bytes || wrap-hash bytes, hex-encoded together.
                let mut buf = key.expose().to_vec();
                buf.extend_from_slice(wrap_hash);
                let encoded = hex::encode(&buf);
                buf.zeroize();
                (id.clone(), encoded)
            })
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
        let mut bytes = hex::decode(key_hex).map_err(|_| CoreError::SessionInvalid)?;
        // key bytes || wrap-hash. Entries without a wrap hash (older
        // sessions) are dropped: without it the key's freshness cannot be
        // proven, and the project simply needs its password again.
        if bytes.len() != crypto::KEY_LEN + 32 {
            bytes.zeroize();
            continue;
        }
        let hash_part: [u8; 32] = bytes[crypto::KEY_LEN..].try_into().expect("length checked");
        bytes.truncate(crypto::KEY_LEN);
        project_keys.insert(id.clone(), (SecretBytes::new(bytes), hash_part));
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

/// The lifecycle state of a session file, for a long-running observed run to
/// watch so that a manual `lock` (which deletes the file) or an auto-lock
/// timeout (the file's recorded `expires_at`) can interrupt it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionFileState {
    /// The file is present and not past its expiry — the session is unlocked.
    Active,
    /// The file is gone (or unreadable/corrupt) — treated as a MANUAL lock.
    Missing,
    /// The file is present but past its recorded expiry — an AUTO-lock (idle).
    Expired,
}

/// Read-only, non-mutating check of a session file's lifecycle at `path`.
///
/// Unlike [`load_and_refresh`], this NEVER slides the expiry forward and NEVER
/// deletes an expired file — it only reports state, so an observed-run lock
/// watch can poll it cheaply without disturbing the session another process
/// owns.
///
/// Only a GENUINELY ABSENT file (`NotFound`) is `Missing` — that is the
/// unambiguous signal of a manual `lock` (which `destroy` deletes the file). A
/// transient read error, or an unparseable/partly-written file, is reported as
/// `Active` (NOT `Missing`): reporting it as missing would spuriously interrupt
/// a still-active run. (Session writes are atomic — see [`write_private`] — so a
/// mid-write partial read should not occur; this is defense in depth.)
pub fn peek_state(path: &std::path::Path) -> SessionFileState {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return SessionFileState::Missing,
        // A transient read error (permissions, EINTR, a momentary rename) is not
        // a lock — do not interrupt the run over it.
        Err(_) => return SessionFileState::Active,
    };
    let file: SessionFile = match serde_json::from_str(&raw) {
        Ok(f) => f,
        // Present but unparseable: not a deletion. Treat as active rather than
        // spuriously interrupting; a real lock deletes the file (NotFound).
        Err(_) => return SessionFileState::Active,
    };
    match &file.expires_at {
        None => SessionFileState::Active, // auto-lock disabled: present == active
        Some(exp) => match clock::parse_rfc3339(exp) {
            Ok(t) if clock::now() >= t => SessionFileState::Expired,
            Ok(_) => SessionFileState::Active,
            // A corrupt expiry on an otherwise-present file: do not spuriously
            // interrupt (a real lock deletes the file).
            Err(_) => SessionFileState::Active,
        },
    }
}

#[cfg(test)]
mod peek_tests {
    use super::*;
    use std::io::Write;

    fn write_session(dir: &std::path::Path, expires_at: Option<&str>) -> std::path::PathBuf {
        let path = dir.join("session.json");
        let exp = match expires_at {
            Some(e) => format!("\"{e}\""),
            None => "null".to_string(),
        };
        let json = format!(
            "{{\"session_id\":\"s1\",\"created_at\":\"2020-01-01T00:00:00Z\",\
              \"expires_at\":{exp},\"ttl_minutes\":15,\"payload_b64\":\"AA==\"}}"
        );
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        path
    }

    #[test]
    fn peek_missing_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            peek_state(&dir.path().join("nope.json")),
            SessionFileState::Missing
        );
    }

    #[test]
    fn peek_future_expiry_is_active() {
        let dir = tempfile::tempdir().unwrap();
        let future = clock::to_rfc3339(clock::now() + time::Duration::hours(1));
        let path = write_session(dir.path(), Some(&future));
        assert_eq!(peek_state(&path), SessionFileState::Active);
    }

    #[test]
    fn peek_past_expiry_is_expired() {
        let dir = tempfile::tempdir().unwrap();
        let past = clock::to_rfc3339(clock::now() - time::Duration::hours(1));
        let path = write_session(dir.path(), Some(&past));
        assert_eq!(peek_state(&path), SessionFileState::Expired);
    }

    #[test]
    fn peek_no_expiry_is_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_session(dir.path(), None);
        assert_eq!(peek_state(&path), SessionFileState::Active);
    }

    #[test]
    fn peek_corrupt_or_partial_file_is_active_not_missing() {
        // A present-but-unparseable file (e.g. a momentary partial read, though
        // writes are atomic) must NOT be reported as Missing — that would
        // spuriously interrupt an active run. Only a genuinely deleted file
        // (a real manual lock) is Missing.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(peek_state(&path), SessionFileState::Active);
    }

    #[test]
    fn peek_deleted_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let future = clock::to_rfc3339(clock::now() + time::Duration::hours(1));
        let path = write_session(dir.path(), Some(&future));
        assert_eq!(peek_state(&path), SessionFileState::Active);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(peek_state(&path), SessionFileState::Missing);
    }
}
