//! Signed items: the only thing that replicates (PROTOCOL.md §3).
//!
//! On the wire and at rest an item is `body_bytes || sig` (the 64-byte
//! signature last), and its hash is `BLAKE3(body_bytes || sig)` — the hash
//! of exactly those bytes. Receivers store and relay the bytes they received
//! and never re-serialize a body.

use super::codec::{decode_body, encode_body, ItemBody, MAX_ITEM_BYTES, SIGNATURE_LEN};
use super::dot::{decode_lower_hex, MeshId};
use super::error::MeshError;
use super::sign::{verify_body_signature, SigningKeyPair};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// BLAKE3 of an item's wire bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ItemHash(pub [u8; 32]);

impl ItemHash {
    pub fn of(wire_bytes: &[u8]) -> Self {
        Self(*blake3::hash(wire_bytes).as_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn parse(s: &str) -> Result<Self, MeshError> {
        decode_lower_hex::<32>(s)
            .map(Self)
            .ok_or(MeshError::Malformed(
                "item hash must be 64 lowercase hex characters",
            ))
    }
}

impl fmt::Display for ItemHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ItemHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ItemHash({})", &self.to_hex()[..16])
    }
}

impl Serialize for ItemHash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ItemHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(|_| serde::de::Error::custom("invalid item hash"))
    }
}

/// An item as signed bytes. Holding a `SignedItem` says nothing about
/// whether its signature has been checked; [`SignedItem::verify_with`] does
/// that and is the only way to a trusted [`ItemBody`].
#[derive(Clone, PartialEq, Eq)]
pub struct SignedItem {
    body_bytes: Vec<u8>,
    sig: [u8; SIGNATURE_LEN],
    hash: ItemHash,
}

impl SignedItem {
    /// Encode `body` canonically and sign it.
    pub fn sign(body: &ItemBody, key: &SigningKeyPair) -> Result<Self, MeshError> {
        let body_bytes = encode_body(body)?;
        let sig = key.sign_body(&body_bytes);
        Self::from_parts(body_bytes, sig)
    }

    /// Assemble from received parts. Checks only the size; the hash is
    /// computed over exactly these bytes.
    pub fn from_parts(body_bytes: Vec<u8>, sig: [u8; SIGNATURE_LEN]) -> Result<Self, MeshError> {
        let size = body_bytes.len() + SIGNATURE_LEN;
        if size > MAX_ITEM_BYTES {
            return Err(MeshError::ItemTooLarge {
                size,
                max: MAX_ITEM_BYTES,
            });
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&body_bytes);
        hasher.update(&sig);
        let hash = ItemHash(*hasher.finalize().as_bytes());
        Ok(Self {
            body_bytes,
            sig,
            hash,
        })
    }

    /// Split wire bytes (`body || sig`) into an item. Ingest check 1 (size).
    pub fn from_wire(bytes: &[u8]) -> Result<Self, MeshError> {
        if bytes.len() > MAX_ITEM_BYTES {
            return Err(MeshError::ItemTooLarge {
                size: bytes.len(),
                max: MAX_ITEM_BYTES,
            });
        }
        if bytes.len() <= SIGNATURE_LEN {
            return Err(MeshError::Malformed("item is shorter than a signature"));
        }
        let (body, sig) = bytes.split_at(bytes.len() - SIGNATURE_LEN);
        let sig: [u8; SIGNATURE_LEN] = sig
            .try_into()
            .map_err(|_| MeshError::Malformed("item is shorter than a signature"))?;
        Self::from_parts(body.to_vec(), sig)
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body_bytes.len() + SIGNATURE_LEN);
        out.extend_from_slice(&self.body_bytes);
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }

    pub fn sig(&self) -> &[u8; SIGNATURE_LEN] {
        &self.sig
    }

    pub fn hash(&self) -> ItemHash {
        self.hash
    }

    pub fn wire_len(&self) -> usize {
        self.body_bytes.len() + SIGNATURE_LEN
    }

    /// Parse the body **without** checking the signature (ingest check 2).
    /// Only for routing — finding the origin whose key verifies it. Nothing
    /// decoded this way may be stored, applied or shown.
    pub fn decode_unverified(&self) -> Result<ItemBody, MeshError> {
        decode_body(&self.body_bytes)
    }

    /// Ingest checks 1-3 and 5: size, parse (canonical), mesh id, signature.
    /// Check 4 (the origin is a known roster member) is the caller's: it
    /// chooses `key`.
    pub fn verify(
        body_bytes: &[u8],
        sig: &[u8; SIGNATURE_LEN],
        key: &VerifyingKey,
        expected_mesh: &MeshId,
    ) -> Result<ItemBody, MeshError> {
        let size = body_bytes.len() + SIGNATURE_LEN;
        if size > MAX_ITEM_BYTES {
            return Err(MeshError::ItemTooLarge {
                size,
                max: MAX_ITEM_BYTES,
            });
        }
        let body = decode_body(body_bytes)?;
        if body.mesh != *expected_mesh {
            return Err(MeshError::WrongMesh);
        }
        verify_body_signature(key, body_bytes, sig)?;
        Ok(body)
    }

    pub fn verify_with(
        &self,
        key: &VerifyingKey,
        expected_mesh: &MeshId,
    ) -> Result<ItemBody, MeshError> {
        Self::verify(&self.body_bytes, &self.sig, key, expected_mesh)
    }
}

impl fmt::Debug for SignedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bodies hold no secret values (credential shares are sealed), but a
        // debug dump of a whole store would be noise; show the identity only.
        f.debug_struct("SignedItem")
            .field("hash", &self.hash)
            .field("len", &self.wire_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::dot::DeviceId;
    use crate::mesh::hlc::Hlc;
    use serde_json::json;

    const FAKE_SECRET: [u8; 32] = [0x5A; 32];

    fn mesh() -> MeshId {
        MeshId::from_bytes([0x11; 16])
    }

    fn body(origin: DeviceId) -> ItemBody {
        ItemBody::new(
            mesh(),
            origin,
            1,
            Hlc::new(1_700_000_000_000, 0),
            "device.info",
            origin.to_hex(),
            json!({"name": "laptop", "listen_addrs": ["127.0.0.1:7000"]}),
        )
    }

    #[test]
    fn sign_verify_round_trip_and_wire_form() {
        let kp = SigningKeyPair::from_secret_bytes(&FAKE_SECRET);
        let origin = DeviceId::from_bytes([0x22; 16]);
        let b = body(origin);
        let item = SignedItem::sign(&b, &kp).unwrap();
        assert_eq!(item.verify_with(&kp.verifying_key(), &mesh()).unwrap(), b);

        let wire = item.to_wire();
        assert_eq!(wire.len(), item.wire_len());
        assert_eq!(
            ItemHash::of(&wire),
            item.hash(),
            "hash = BLAKE3(wire bytes)"
        );
        let back = SignedItem::from_wire(&wire).unwrap();
        assert_eq!(back, item);
        assert_eq!(back.decode_unverified().unwrap(), b);
        // Ed25519 is deterministic and the codec canonical: same body, same item.
        assert_eq!(SignedItem::sign(&b, &kp).unwrap(), item);
    }

    #[test]
    fn wrong_mesh_and_wrong_key_are_refused() {
        let kp = SigningKeyPair::from_secret_bytes(&FAKE_SECRET);
        let other = SigningKeyPair::generate();
        let item = SignedItem::sign(&body(DeviceId::from_bytes([0x22; 16])), &kp).unwrap();
        assert_eq!(
            item.verify_with(&kp.verifying_key(), &MeshId::from_bytes([0x99; 16])),
            Err(MeshError::WrongMesh)
        );
        assert_eq!(
            item.verify_with(&other.verifying_key(), &mesh()),
            Err(MeshError::BadSignature)
        );
    }

    #[test]
    fn short_and_oversize_wire_items_are_refused() {
        assert!(SignedItem::from_wire(&[0u8; SIGNATURE_LEN]).is_err());
        assert!(SignedItem::from_wire(&[]).is_err());
        assert!(matches!(
            SignedItem::from_wire(&vec![b'x'; MAX_ITEM_BYTES + 1]),
            Err(MeshError::ItemTooLarge { .. })
        ));
        assert!(matches!(
            SignedItem::from_parts(vec![b'x'; MAX_ITEM_BYTES], [0; SIGNATURE_LEN]),
            Err(MeshError::ItemTooLarge { .. })
        ));
    }

    #[test]
    fn hash_hex_round_trips() {
        let h = ItemHash::of(b"abc");
        assert_eq!(ItemHash::parse(&h.to_hex()).unwrap(), h);
        assert!(ItemHash::parse("abc").is_err());
    }
}
