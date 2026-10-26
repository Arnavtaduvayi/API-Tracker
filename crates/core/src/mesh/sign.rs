//! Ed25519 item signing (PROTOCOL.md §3).
//!
//! `sig = Ed25519(sign_key, "tethra-mesh/v1/item\0" || body_bytes)`.
//!
//! The domain prefix keeps an item signature from ever being valid for any
//! other message this key might sign in a later protocol. Verification uses
//! `verify_strict`, which also rejects small-order keys and points: an item
//! hash covers the signature bytes, so a malleable signature would let a relay
//! mint a second "valid" encoding of the same item and fake a fork.

use super::dot::decode_lower_hex;
use super::error::MeshError;
use crate::secret::REDACTED;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

/// Domain-separation prefix for item signatures.
pub const ITEM_SIGNATURE_DOMAIN: &[u8] = b"tethra-mesh/v1/item\0";

/// A device's Ed25519 item-signing key. The secret half is wiped on drop and
/// never printed.
pub struct SigningKeyPair {
    key: SigningKey,
}

impl SigningKeyPair {
    /// A fresh key from the operating system RNG.
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(secret.as_mut()).expect("operating system RNG is unavailable");
        Self::from_secret_bytes(&secret)
    }

    /// Rebuild from the 32-byte secret (after unwrapping it from the vault).
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(secret),
        }
    }

    /// The 32-byte secret, for wrapping under the vault key. Every call site
    /// is a deliberate exposure, like [`crate::secret::SecretBytes::expose`].
    pub fn expose_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn public_key(&self) -> PublicKeyBytes {
        PublicKeyBytes(self.key.verifying_key().to_bytes())
    }

    /// Sign a canonical body (the domain prefix is added here).
    pub(crate) fn sign_body(&self, body_bytes: &[u8]) -> [u8; 64] {
        self.key.sign(&signed_message(body_bytes)).to_bytes()
    }
}

impl fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeyPair")
            .field("public", &self.public_key())
            .field("secret", &REDACTED)
            .finish()
    }
}

impl fmt::Display for SigningKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed25519 signing key (public {})", self.public_key())
    }
}

fn signed_message(body_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ITEM_SIGNATURE_DOMAIN.len() + body_bytes.len());
    msg.extend_from_slice(ITEM_SIGNATURE_DOMAIN);
    msg.extend_from_slice(body_bytes);
    msg
}

/// Verify an item signature with the origin's key.
pub fn verify_body_signature(
    key: &VerifyingKey,
    body_bytes: &[u8],
    sig: &[u8; 64],
) -> Result<(), MeshError> {
    key.verify_strict(&signed_message(body_bytes), &Signature::from_bytes(sig))
        .map_err(|_| MeshError::BadSignature)
}

/// A 32-byte public key (Ed25519 signing, X25519 Noise or X25519 sealing),
/// written as 64 lowercase hex characters. Public keys are not secret.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKeyBytes(pub [u8; 32]);

impl PublicKeyBytes {
    pub fn parse(s: &str) -> Result<Self, MeshError> {
        decode_lower_hex::<32>(s)
            .map(Self)
            .ok_or(MeshError::InvalidKey)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Interpret as an Ed25519 verifying key, refusing invalid encodings and
    /// small-order ("weak") keys.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, MeshError> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| MeshError::InvalidKey)?;
        if vk.is_weak() {
            return Err(MeshError::InvalidKey);
        }
        Ok(vk)
    }
}

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKeyBytes({})", self.to_hex())
    }
}

impl Serialize for PublicKeyBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s)
            .map_err(|_| serde::de::Error::custom("public key must be 64 lowercase hex characters"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unmistakably fake secret: 0x5A repeated.
    const FAKE_SECRET: [u8; 32] = [0x5A; 32];

    #[test]
    fn debug_and_display_never_print_the_secret() {
        let kp = SigningKeyPair::from_secret_bytes(&FAKE_SECRET);
        let secret_hex = hex::encode(FAKE_SECRET);
        let secret_dec = format!("{:?}", FAKE_SECRET);
        for rendered in [format!("{kp:?}"), format!("{kp:#?}"), format!("{kp}")] {
            assert!(!rendered.contains(&secret_hex), "{rendered}");
            assert!(!rendered.contains(&secret_dec), "{rendered}");
            assert!(!rendered.contains("90, 90, 90"), "{rendered}");
            assert!(rendered.contains(&kp.public_key().to_hex()));
        }
        assert!(format!("{kp:?}").contains(REDACTED));
    }

    #[test]
    fn secret_round_trips_through_its_bytes() {
        let kp = SigningKeyPair::generate();
        let again = SigningKeyPair::from_secret_bytes(&kp.expose_secret_bytes());
        assert_eq!(kp.public_key(), again.public_key());
        assert_ne!(
            SigningKeyPair::generate().public_key(),
            kp.public_key(),
            "keys come from the OS RNG"
        );
    }

    #[test]
    fn signatures_are_domain_separated() {
        let kp = SigningKeyPair::from_secret_bytes(&FAKE_SECRET);
        let body = br#"{"v":1}"#;
        let sig = kp.sign_body(body);
        let vk = kp.verifying_key();
        assert!(verify_body_signature(&vk, body, &sig).is_ok());
        // The same key signing the raw body without the prefix does not
        // produce an item signature.
        let raw = kp.key.sign(body).to_bytes();
        assert_eq!(
            verify_body_signature(&vk, body, &raw),
            Err(MeshError::BadSignature)
        );
    }

    #[test]
    fn public_key_parsing_rejects_bad_and_weak_keys() {
        let kp = SigningKeyPair::from_secret_bytes(&FAKE_SECRET);
        let pk = kp.public_key();
        assert_eq!(PublicKeyBytes::parse(&pk.to_hex()).unwrap(), pk);
        assert!(pk.to_verifying_key().is_ok());
        assert!(PublicKeyBytes::parse(&pk.to_hex().to_uppercase()).is_err());
        assert!(PublicKeyBytes::parse("00").is_err());
        // The identity point (small order) is a valid encoding but weak.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            PublicKeyBytes(identity).to_verifying_key(),
            Err(MeshError::InvalidKey)
        );
    }
}
