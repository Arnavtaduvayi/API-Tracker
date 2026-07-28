//! Encrypted `.env` restore values (ADR 0028).
//!
//! # The problem this solves
//!
//! Linking a project to the gateway rewrites `OPENAI_BASE_URL` (and its
//! peers) in the user's `.env`. To undo that, Tethra records what the
//! variable held before. Those recorded values *are* the user's
//! credentials in every case where the variable held one.
//!
//! The audited head decided what was safe to record with a shape
//! predicate, `prior_value_is_recordable`. The re-audit showed the
//! predicate admitting values the codebase's **own** secret detector
//! flagged as key material — an `sk-proj-…` key, an `AKIA…:…` pair, and a
//! JWT of exactly the shape `SUPABASE_SERVICE_ROLE_KEY` uses, which is a
//! full RLS-bypassing admin credential for a provider in this very catalog
//! (RA-006). It then wrote them verbatim into
//! `gateway_project_links.prior_env_json`, a plain `TEXT` column of a
//! SQLite file opened with no `PRAGMA key`.
//!
//! # The fix
//!
//! Stop asking whether a value is secret. Every recorded value is sealed
//! under a vault-wrapped key, so a plaintext credential is not something
//! the code can produce even if a future predicate is wrong.
//!
//! What stays in the clear is deliberately only the *structure*: which file,
//! which variable, whether the file existed, and whether a value was
//! recorded at all. That keeps `unlink`'s reporting honest and keeps the
//! gateway service's read-only "is there a restore record?" check working
//! without giving it a key it must never hold.
//!
//! # Failing safely
//!
//! Sealing needs an unlocked vault. Every production path that records or
//! restores a value has one. When a caller cannot supply the handle, the
//! value is **withheld** — recorded as absent, and surfaced to the user as
//! a warning — never written in the clear. "We could not protect it" and
//! "it is fine to store" must not resolve to the same behaviour, which is
//! precisely how RA-006 happened.

use crate::crypto::{self, aad};
use crate::error::{CoreError, Result};
use crate::secret::{SecretBytes, SecretString};
use serde::{Deserialize, Serialize};

/// A sealed prior value: ciphertext only, hex-encoded for JSON.
///
/// `Debug` is derived and safe: the struct holds no plaintext. The AAD
/// binds the ciphertext to its link, file and variable, so a sealed value
/// cannot be transplanted onto a different variable and still open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedValue {
    /// Hex-encoded XChaCha20-Poly1305 ciphertext.
    pub ct: String,
}

/// Seals and opens restore records for one vault.
///
/// Held only by a process with an unlocked vault. Deliberately **not**
/// `Clone`: a decrypting key should not be duplicated casually, and every
/// caller can borrow one.
pub struct RestoreCrypto {
    vault_id: String,
    key: SecretBytes,
}

impl std::fmt::Debug for RestoreCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key, and never render the vault id next to
        // something that looks like key material.
        f.write_str("RestoreCrypto { key: REDACTED }")
    }
}

impl RestoreCrypto {
    pub fn new(vault_id: String, key: SecretBytes) -> Self {
        RestoreCrypto { vault_id, key }
    }

    /// Seal one prior value.
    ///
    /// `link_slug`, `path` and `key_name` are bound into the associated
    /// data, so moving a ciphertext to another variable, another file or
    /// another link makes it fail to open rather than silently restore the
    /// wrong secret somewhere else.
    pub fn seal(
        &self,
        link_slug: &str,
        path: &str,
        key_name: &str,
        value: &str,
    ) -> Result<SealedValue> {
        let ct = crypto::encrypt(
            &self.key,
            &aad::env_restore_value(&self.vault_id, link_slug, path, key_name),
            value.as_bytes(),
        )?;
        Ok(SealedValue {
            ct: hex::encode(ct),
        })
    }

    /// Open one sealed prior value.
    ///
    /// The plaintext comes back inside a [`SecretString`], which redacts
    /// itself in `Debug`/`Display` and zeroizes on drop, so a restore value
    /// cannot reach a log or an error message by accident.
    pub fn open(
        &self,
        link_slug: &str,
        path: &str,
        key_name: &str,
        sealed: &SealedValue,
    ) -> Result<SecretString> {
        let bytes = hex::decode(&sealed.ct)
            .map_err(|_| CoreError::VaultCorrupted("restore record ciphertext is not valid hex"))?;
        let plain = crypto::decrypt(
            &self.key,
            &aad::env_restore_value(&self.vault_id, link_slug, path, key_name),
            &bytes,
            "env restore value",
        )?;
        let text = String::from_utf8(plain.expose().to_vec())
            .map_err(|_| CoreError::VaultCorrupted("restore record plaintext is not UTF-8"))?;
        Ok(SecretString::new(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto_for(vault: &str) -> RestoreCrypto {
        RestoreCrypto::new(vault.to_string(), crypto::new_key())
    }

    #[test]
    fn a_sealed_value_round_trips() {
        let c = crypto_for("v1");
        let sealed = c
            .seal("slug", ".env", "OPENAI_API_KEY", "sk-proj-SECRET")
            .unwrap();
        let opened = c.open("slug", ".env", "OPENAI_API_KEY", &sealed).unwrap();
        assert_eq!(opened.expose(), "sk-proj-SECRET");
    }

    #[test]
    fn the_ciphertext_never_contains_the_plaintext() {
        let c = crypto_for("v1");
        let sealed = c
            .seal("slug", ".env", "OPENAI_API_KEY", "sk-proj-CANARY-8f21ab")
            .unwrap();
        assert!(!sealed.ct.contains("CANARY"));
        assert!(!sealed.ct.contains("sk-proj"));
        let json = serde_json::to_string(&sealed).unwrap();
        assert!(
            !json.contains("CANARY"),
            "the serialized form must not carry the plaintext: {json}"
        );
    }

    #[test]
    fn a_sealed_value_cannot_be_transplanted() {
        let c = crypto_for("v1");
        let sealed = c
            .seal("slug", ".env", "OPENAI_API_KEY", "sk-secret")
            .unwrap();
        for (slug, path, key) in [
            ("other-slug", ".env", "OPENAI_API_KEY"),
            ("slug", "other/.env", "OPENAI_API_KEY"),
            ("slug", ".env", "ANTHROPIC_API_KEY"),
        ] {
            assert!(
                c.open(slug, path, key, &sealed).is_err(),
                "a ciphertext moved to ({slug}, {path}, {key}) must not open"
            );
        }
    }

    #[test]
    fn another_vaults_key_cannot_open_it() {
        let a = crypto_for("v1");
        let b = crypto_for("v1");
        let sealed = a.seal("slug", ".env", "K", "secret").unwrap();
        assert!(b.open("slug", ".env", "K", &sealed).is_err());
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected_not_silently_wrong() {
        let c = crypto_for("v1");
        let mut sealed = c.seal("slug", ".env", "K", "secret").unwrap();
        // Flip the last hex nibble.
        let last = sealed.ct.pop().unwrap();
        sealed.ct.push(if last == '0' { '1' } else { '0' });
        assert!(c.open("slug", ".env", "K", &sealed).is_err());
    }

    #[test]
    fn debug_never_renders_the_key() {
        let c = crypto_for("v1");
        let text = format!("{c:?}");
        assert!(text.contains("REDACTED"), "{text}");
    }
}
