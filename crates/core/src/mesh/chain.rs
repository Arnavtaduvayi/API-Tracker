//! Per-origin dot chains and held-item digests (PROTOCOL.md §7.1, §8.5).
//!
//! A device's dot log records the hash it accepted at every dot of every
//! origin up to its version vector. The chain folds that log into one value
//! per seq, so two devices can compare a whole history with one hash and find
//! the first difference by bisection. The digest summarises the items a device
//! *holds* for one origin, for repair.

use super::error::MeshError;
use super::item::ItemHash;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// BLAKE3 key-derivation context for chain steps.
pub const CHAIN_CONTEXT: &str = "tethra-mesh v1 dot chain";
/// BLAKE3 key-derivation context for per-origin held-item digests.
pub const DIGEST_CONTEXT: &str = "tethra-mesh v1 origin digest";

/// A 32-byte chain value or digest, written as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// `chain(o, 0)`.
    pub const ZERO: Hash32 = Hash32([0; 32]);

    /// `chain(o, s) = derive_key(CHAIN_CONTEXT, chain(o, s - 1) || hash(o, s))`.
    pub fn chain_next(&self, item: &ItemHash) -> Hash32 {
        let mut h = blake3::Hasher::new_derive_key(CHAIN_CONTEXT);
        h.update(&self.0);
        h.update(&item.0);
        Hash32(*h.finalize().as_bytes())
    }

    /// The digest of a set of held item hashes (order-independent: sorted
    /// first).
    pub fn digest_of(hashes: impl IntoIterator<Item = ItemHash>) -> Hash32 {
        let mut all: Vec<ItemHash> = hashes.into_iter().collect();
        all.sort_unstable();
        let mut h = blake3::Hasher::new_derive_key(DIGEST_CONTEXT);
        for x in &all {
            h.update(&x.0);
        }
        Hash32(*h.finalize().as_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn parse(s: &str) -> Result<Self, MeshError> {
        super::dot::decode_lower_hex::<32>(s)
            .map(Hash32)
            .ok_or(MeshError::Malformed(
                "hash must be 64 lowercase hex characters",
            ))
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(|_| serde::de::Error::custom("invalid 32-byte hash"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chains_differ_forever_after_the_first_difference() {
        let (a, b, c) = (ItemHash([1; 32]), ItemHash([2; 32]), ItemHash([3; 32]));
        let x = Hash32::ZERO.chain_next(&a).chain_next(&b).chain_next(&c);
        let y = Hash32::ZERO.chain_next(&a).chain_next(&c).chain_next(&c);
        assert_ne!(x, y);
        assert_eq!(x, Hash32::ZERO.chain_next(&a).chain_next(&b).chain_next(&c));
        assert_ne!(Hash32::ZERO.chain_next(&a), Hash32::ZERO.chain_next(&b));
    }

    #[test]
    fn digests_ignore_order() {
        let (a, b) = (ItemHash([1; 32]), ItemHash([2; 32]));
        assert_eq!(Hash32::digest_of([a, b]), Hash32::digest_of([b, a]));
        assert_ne!(Hash32::digest_of([a]), Hash32::digest_of([a, b]));
    }

    #[test]
    fn hex_round_trip() {
        let h = Hash32([0xab; 32]);
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<Hash32>(&json).unwrap(), h);
        assert!(Hash32::parse("AB").is_err());
    }
}
