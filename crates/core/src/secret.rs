//! Redacting wrappers for secret material.
//!
//! Everything that ever holds a plaintext credential value, password, or raw
//! key must live in one of these types. They:
//! - print `[REDACTED]` from `Debug` and `Display`,
//! - serialize as `[REDACTED]` (so secrets can never leak through accidental
//!   `serde_json::to_string` of a containing struct),
//! - zeroize their backing memory when dropped.
//!
//! Reading the actual value requires an explicit `expose()` call, which keeps
//! every access grep-able.

use serde::{Serialize, Serializer};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The placeholder emitted anywhere a secret would otherwise appear.
pub const REDACTED: &str = "[REDACTED]";

/// A UTF-8 secret (passwords, credential values).
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Explicitly read the secret. Every call site is a deliberate exposure.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Constant-time equality, for comparing secret values without timing
    /// side channels.
    pub fn ct_eq(&self, other: &SecretString) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

/// Raw secret bytes (derived keys, random keys, decrypted buffers).
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Explicitly read the secret bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn ct_eq(&self, other: &SecretBytes) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE: &str = "FAKE-TEST-NOT-A-REAL-KEY-000001";

    #[test]
    fn secret_string_redacts_debug_display_serde() {
        let s = SecretString::from(FAKE);
        assert_eq!(format!("{s:?}"), REDACTED);
        assert_eq!(format!("{s}"), REDACTED);
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains(FAKE));
        assert!(json.contains(REDACTED));
        assert_eq!(s.expose(), FAKE);
    }

    #[test]
    fn secret_bytes_redacts_debug_serde() {
        let s = SecretBytes::from(FAKE.as_bytes().to_vec());
        assert_eq!(format!("{s:?}"), REDACTED);
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains(FAKE));
    }

    #[test]
    fn constant_time_eq_works() {
        let a = SecretString::from(FAKE);
        let b = SecretString::from(FAKE);
        let c = SecretString::from("FAKE-TEST-NOT-A-REAL-KEY-000002");
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}
