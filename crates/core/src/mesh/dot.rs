//! Identifiers and dots.
//!
//! Every mesh identifier is 16 random bytes written as 32 lowercase hex
//! characters. The textual form is the only accepted form on the wire, so
//! one identifier has exactly one encoding and identifiers sort the same way
//! as bytes or as strings.

use super::error::MeshError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// True when `s` is exactly `2 * len` lowercase hex characters.
pub(crate) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == 2 * len && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Decode a canonical lowercase hex string into a fixed-size array.
pub(crate) fn decode_lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if !is_lower_hex(s, N) {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

macro_rules! hex_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const LEN: usize = 16;
            /// The smallest and largest ids, for range scans over ordered maps.
            pub const MIN: Self = Self([0; 16]);
            pub const MAX: Self = Self([0xff; 16]);

            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// A fresh identifier from the operating system RNG.
            pub fn random() -> Self {
                let mut b = [0u8; 16];
                getrandom::fill(&mut b).expect("operating system RNG is unavailable");
                Self(b)
            }

            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parse the canonical form: exactly 32 lowercase hex characters.
            pub fn parse(s: &str) -> Result<Self, MeshError> {
                decode_lower_hex::<16>(s).map(Self).ok_or(MeshError::InvalidId)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = MeshError;
            fn from_str(s: &str) -> Result<Self, MeshError> {
                Self::parse(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::parse(&s).map_err(|_| {
                    serde::de::Error::custom(concat!(
                        stringify!($name),
                        " must be 32 lowercase hex characters"
                    ))
                })
            }
        }
    };
}

hex_id!(
    /// One Tethra installation's mesh identity (one data directory, not one
    /// machine). Random; never derived from anything, never reused.
    DeviceId
);
hex_id!(
    /// The random identifier of one mesh.
    MeshId
);
hex_id!(
    /// A shared project's mesh-wide identifier (local project ids never
    /// replicate).
    MeshProjectId
);
hex_id!(
    /// A spend cap's identifier.
    CapId
);
hex_id!(
    /// One credential share (Increment 11).
    ShareId
);
hex_id!(
    /// A stable reference to one shared credential across reshares
    /// (Increment 11).
    CredentialRef
);

/// An item's unique position in its origin's log.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Dot {
    pub origin: DeviceId,
    pub seq: u64,
}

impl Dot {
    pub const fn new(origin: DeviceId, seq: u64) -> Self {
        Self { origin, seq }
    }
}

impl fmt::Display for Dot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.origin, self.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_round_trips_and_is_canonical() {
        let id = DeviceId::random();
        let s = id.to_string();
        assert_eq!(s.len(), 32);
        assert_eq!(DeviceId::parse(&s).unwrap(), id);
        assert_eq!(s.parse::<DeviceId>().unwrap(), id);
        assert!(DeviceId::parse(&s.to_uppercase()).is_err() || s == s.to_uppercase());
        assert!(DeviceId::parse("ABCDEF0123456789ABCDEF0123456789").is_err());
        assert!(DeviceId::parse("0123").is_err());
        assert!(DeviceId::parse("0123456789abcdef0123456789abcdeg").is_err());
        assert!(DeviceId::parse(" 0123456789abcdef0123456789abcde").is_err());
    }

    #[test]
    fn ids_order_like_their_hex_strings() {
        let a = DeviceId::from_bytes([0x00; 16]);
        let b = DeviceId::from_bytes([0x0f; 16]);
        let c = DeviceId::from_bytes([0xa0; 16]);
        assert!(a < b && b < c);
        assert!(a.to_string() < b.to_string() && b.to_string() < c.to_string());
    }

    #[test]
    fn ids_serialize_as_hex_strings_and_reject_bad_forms() {
        let id = MeshId::from_bytes([0xab; 16]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(16)));
        assert_eq!(serde_json::from_str::<MeshId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<MeshId>("\"AB\"").is_err());
        assert!(serde_json::from_str::<MeshId>("12").is_err());
    }

    #[test]
    fn dots_order_by_origin_then_seq() {
        let a = DeviceId::from_bytes([1; 16]);
        let b = DeviceId::from_bytes([2; 16]);
        assert!(Dot::new(a, 9) < Dot::new(b, 1));
        assert!(Dot::new(a, 1) < Dot::new(a, 2));
        assert_eq!(Dot::new(a, 3).to_string(), format!("{a}:3"));
    }
}
