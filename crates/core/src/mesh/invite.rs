//! Invites and the pairing messages (Increment 04, DESIGN §D10, PROTOCOL.md
//! §9). Pure: no I/O.
//!
//! An invite is a 20-byte random **token**, a bearer secret for its lifetime
//! (10 minutes by default, 60 at most), shown once as
//!
//! ```text
//! tethra-mesh-invite:v1:<32 base32 chars of token><2 checksum chars>@<host:port>[,<host:port>…]
//! ```
//!
//! The two checksum characters catch typos before any connection is made.
//! From the token come:
//! - the **pairing psk**: `BLAKE3-derive_key("tethra-mesh v1 pairing psk", token)`;
//! - its **hash** `BLAKE3(token)`, which is what the inviter's database keys the
//!   invite by;
//! - the **hint**, the hash's first 8 bytes, which the joiner sends in the clear
//!   so the inviter can find the invite. A hint does not help anyone recover
//!   the token or the psk.

use super::dot::{DeviceId, MeshId};
use super::error::MeshError;
use super::sign::PublicKeyBytes;
use crate::secret::{SecretString, REDACTED};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

pub const INVITE_PREFIX: &str = "tethra-mesh-invite:v1:";
pub const TOKEN_LEN: usize = 20;
pub const HINT_LEN: usize = 8;
/// Default and maximum invite lifetime, in minutes.
pub const DEFAULT_TTL_MINUTES: u32 = 10;
pub const MAX_TTL_MINUTES: u32 = 60;
/// Wrong pairing attempts after which an invite is dead.
pub const MAX_ATTEMPTS: u32 = 5;
const MAX_ADDRS: usize = 8;
const MAX_ADDR_LEN: usize = 255;
const PSK_CONTEXT: &str = "tethra-mesh v1 pairing psk";
const CHECKSUM_CONTEXT: &str = "tethra-mesh v1 invite checksum";
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The invite token. Never printed except once, inside the invite string.
#[derive(Clone)]
pub struct InviteToken(Zeroizing<[u8; TOKEN_LEN]>);

impl InviteToken {
    pub fn generate() -> Self {
        let mut t = Zeroizing::new([0u8; TOKEN_LEN]);
        getrandom::fill(t.as_mut()).expect("operating system RNG is unavailable");
        Self(t)
    }

    pub fn from_bytes(bytes: [u8; TOKEN_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// `BLAKE3(token)`: the inviter's key for the invite.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(self.0.as_ref()).as_bytes()
    }

    /// The first 8 bytes of [`Self::hash`], sent in the clear when pairing.
    pub fn hint(&self) -> [u8; HINT_LEN] {
        hint_of(&self.hash())
    }

    /// The pairing handshake's psk.
    pub fn pairing_psk(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(PSK_CONTEXT, self.0.as_ref()))
    }

    fn base32(&self) -> Zeroizing<String> {
        Zeroizing::new(base32_encode(self.0.as_ref()))
    }
}

impl fmt::Debug for InviteToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// The hint of a stored invite hash.
pub fn hint_of(hash: &[u8; 32]) -> [u8; HINT_LEN] {
    let mut h = [0u8; HINT_LEN];
    h.copy_from_slice(&hash[..HINT_LEN]);
    h
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|a| *a == c).map(|p| p as u32)
}

fn checksum(token_b32: &str, addrs: &str) -> [u8; 2] {
    let mut h = blake3::Hasher::new_derive_key(CHECKSUM_CONTEXT);
    h.update(token_b32.as_bytes());
    h.update(b"@");
    h.update(addrs.as_bytes());
    let d = h.finalize();
    let b = d.as_bytes();
    [
        ALPHABET[(b[0] & 31) as usize],
        ALPHABET[(b[1] & 31) as usize],
    ]
}

fn valid_addr(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= MAX_ADDR_LEN
        && a.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0)
        })
        && a.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']' | '_'))
}

/// Format the invite string. It contains the token, so it is a secret.
pub fn format_invite(token: &InviteToken, addrs: &[String]) -> Result<SecretString, MeshError> {
    if addrs.is_empty() || addrs.len() > MAX_ADDRS || !addrs.iter().all(|a| valid_addr(a)) {
        return Err(MeshError::InvalidInvite(
            "give 1-8 addresses of the form host:port",
        ));
    }
    let t = token.base32();
    let joined = addrs.join(",");
    let c = checksum(&t, &joined);
    Ok(SecretString::new(format!(
        "{INVITE_PREFIX}{}{}{}@{joined}",
        t.as_str(),
        c[0] as char,
        c[1] as char
    )))
}

/// Parse an invite string. Every error is a static description; none echoes
/// the input, which holds the token.
pub fn parse_invite(s: &str) -> Result<(InviteToken, Vec<String>), MeshError> {
    let s = s.trim();
    let rest = s
        .strip_prefix(INVITE_PREFIX)
        .ok_or(MeshError::InvalidInvite(
            "it does not start with tethra-mesh-invite:v1:",
        ))?;
    let (secret, addrs) = rest
        .split_once('@')
        .ok_or(MeshError::InvalidInvite("it has no addresses"))?;
    let b32_len = (TOKEN_LEN * 8).div_ceil(5);
    if secret.len() != b32_len + 2 || !secret.bytes().all(|c| base32_value(c).is_some()) {
        return Err(MeshError::InvalidInvite(
            "the code is not 34 characters of a-z and 2-7",
        ));
    }
    let (t, c) = secret.split_at(b32_len);
    if checksum(t, addrs).as_slice() != c.as_bytes() {
        return Err(MeshError::InvalidInvite(
            "its checksum does not match (check for a typo)",
        ));
    }
    let mut bytes = Zeroizing::new([0u8; TOKEN_LEN]);
    let (mut acc, mut bits, mut i) = (0u64, 0u32, 0usize);
    for c in t.bytes() {
        acc = (acc << 5) | u64::from(base32_value(c).expect("checked above"));
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if i < TOKEN_LEN {
                bytes[i] = (acc >> bits) as u8;
            }
            i += 1;
        }
    }
    let addrs: Vec<String> = addrs.split(',').map(str::to_owned).collect();
    if addrs.len() > MAX_ADDRS || !addrs.iter().all(|a| valid_addr(a)) {
        return Err(MeshError::InvalidInvite("an address is not host:port"));
    }
    Ok((InviteToken(bytes), addrs))
}

/// A mesh access key (the psk of member sessions). Redacted in `Debug`;
/// serialized as hex only inside encrypted frames.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessKey(pub Zeroizing<[u8; 32]>);

impl AccessKey {
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for AccessKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&Zeroizing::new(hex::encode(self.0.as_ref())))
    }
}

impl<'de> Deserialize<'de> for AccessKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        let bytes = super::dot::decode_lower_hex::<32>(&s)
            .ok_or_else(|| serde::de::Error::custom("access key must be 64 lowercase hex"))?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}

/// The joiner's first frame inside the pairing channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    pub name: String,
    pub sign_pub: PublicKeyBytes,
    pub noise_pub: PublicKeyBytes,
    pub seal_pub: PublicKeyBytes,
}

/// The inviter's reply: everything the joiner needs to become a member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairAccept {
    pub mesh_id: MeshId,
    /// The device that ran `mesh init` (ADR 0031 R6).
    pub genesis: DeviceId,
    pub inviter: DeviceId,
    pub access_epoch: u32,
    pub access_key: AccessKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs() -> Vec<String> {
        vec!["127.0.0.1:7420".into(), "laptop.tail1.ts.net:7420".into()]
    }

    #[test]
    fn invites_round_trip_and_reveal_nothing_in_debug() {
        let t = InviteToken::from_bytes([0xab; 20]);
        let s = format_invite(&t, &addrs()).unwrap();
        assert!(s.expose().starts_with(INVITE_PREFIX));
        let (back, a) = parse_invite(s.expose()).unwrap();
        assert_eq!(back.hash(), t.hash());
        assert_eq!(a, addrs());
        assert_eq!(format!("{t:?}"), REDACTED);
        assert_eq!(format!("{s:?}"), REDACTED);
        let k = AccessKey(Zeroizing::new([7; 32]));
        assert!(!format!("{k:?}").contains("0707"));
    }

    #[test]
    fn a_typo_anywhere_is_caught_by_the_checksum() {
        let t = InviteToken::from_bytes([0x5a; 20]);
        let s = format_invite(&t, &addrs()).unwrap();
        let s = s.expose();
        let start = INVITE_PREFIX.len();
        let mut caught = 0;
        let mut tried = 0;
        for i in start..start + 34 {
            for c in ALPHABET.iter().copied() {
                let mut b = s.as_bytes().to_vec();
                if b[i] == c {
                    continue;
                }
                b[i] = c;
                tried += 1;
                if parse_invite(std::str::from_utf8(&b).unwrap()).is_err() {
                    caught += 1;
                }
            }
        }
        // Two base32 characters: about 1 in 1 024 single-character typos slip.
        assert!(caught * 1000 >= tried * 995, "{caught}/{tried}");
        let wrong_addr = s.replace("7420,", "7421,");
        assert!(parse_invite(&wrong_addr).is_err());
    }

    #[test]
    fn malformed_invites_are_refused_without_echoing_them() {
        for bad in [
            "",
            "tethra-mesh-invite:v2:abc@1.2.3.4:1",
            "tethra-mesh-invite:v1:short@1.2.3.4:1",
            "tethra-mesh-invite:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let e = parse_invite(bad).unwrap_err();
            assert!(
                !bad.is_empty() && !e.to_string().contains(&bad[..bad.len().min(30)])
                    || bad.is_empty()
            );
        }
        let t = InviteToken::generate();
        assert!(format_invite(&t, &[]).is_err());
        assert!(format_invite(&t, &["no-port".into()]).is_err());
        assert!(format_invite(&t, &["a b:1".into()]).is_err());
    }

    #[test]
    fn psk_hash_and_hint_are_derived_and_distinct() {
        let t = InviteToken::from_bytes([1; 20]);
        assert_eq!(t.hint(), hint_of(&t.hash()));
        assert_ne!(&t.pairing_psk()[..], &t.hash()[..]);
        let u = InviteToken::from_bytes([2; 20]);
        assert_ne!(t.hint(), u.hint());
    }
}
