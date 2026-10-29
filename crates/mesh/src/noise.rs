//! Noise handshakes (DESIGN §D10, PROTOCOL.md §9).
//!
//! - **Sessions** between members: `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s`, psk =
//!   the mesh access key, prologue `"tethra-mesh/v1\0" || mesh_id`. With the psk
//!   mixed in before the first message, a prober without the access key fails
//!   at message 1 and never sees a device's static key.
//! - **Pairing**: `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`, psk =
//!   `blake3::derive_key("tethra-mesh v1 pairing psk", token)`, prologue
//!   `"tethra-mesh/v1-pair\0"`.
//!
//! Our copies of private keys and psks live in `Zeroizing` buffers. `snow` 0.10
//! keeps its own copies inside the handshake and cipher states and does not
//! zeroize them (KNOWN_LIMITATIONS).

use snow::{Builder, HandshakeState};

pub const SESSION_PATTERN: &str = "Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s";
pub const PAIR_PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
pub const PAIR_PROLOGUE: &[u8] = b"tethra-mesh/v1-pair\0";

/// `"tethra-mesh/v1\0" || mesh_id` (the 16 raw id bytes).
pub fn session_prologue(mesh_id: &[u8; 16]) -> Vec<u8> {
    let mut p = b"tethra-mesh/v1\0".to_vec();
    p.extend_from_slice(mesh_id);
    p
}

fn build(
    pattern: &str,
    psk_location: u8,
    psk: &[u8; 32],
    static_secret: &[u8; 32],
    prologue: &[u8],
    initiator: bool,
) -> Result<HandshakeState, snow::Error> {
    let params = pattern.parse()?;
    let b = Builder::new(params)
        .local_private_key(static_secret)?
        .psk(psk_location, psk)?
        .prologue(prologue)?;
    if initiator {
        b.build_initiator()
    } else {
        b.build_responder()
    }
}

/// A member session handshake (psk0 with the access key).
pub fn session(
    mesh_id: &[u8; 16],
    access_key: &[u8; 32],
    static_secret: &[u8; 32],
    initiator: bool,
) -> Result<HandshakeState, snow::Error> {
    build(
        SESSION_PATTERN,
        0,
        access_key,
        static_secret,
        &session_prologue(mesh_id),
        initiator,
    )
}

/// A pairing handshake (psk3 with the invite's pairing psk).
pub fn pairing(
    pairing_psk: &[u8; 32],
    static_secret: &[u8; 32],
    initiator: bool,
) -> Result<HandshakeState, snow::Error> {
    build(
        PAIR_PATTERN,
        3,
        pairing_psk,
        static_secret,
        PAIR_PROLOGUE,
        initiator,
    )
}
