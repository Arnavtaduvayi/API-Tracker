//! The `snow` spike (Increment 04): both handshake patterns of DESIGN §D10
//! complete, and a wrong psk fails at message 1 — before the responder sends
//! anything, so a prober never sees its static key.

use api_tracker_mesh::noise;

fn key(b: u8) -> [u8; 32] {
    let mut k = [b; 32];
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

fn run(mut i: snow::HandshakeState, mut r: snow::HandshakeState) -> Result<(), snow::Error> {
    let mut buf = vec![0u8; 1024];
    let mut out = vec![0u8; 1024];
    let n = i.write_message(&[], &mut buf)?;
    r.read_message(&buf[..n], &mut out)?;
    let n = r.write_message(&[], &mut buf)?;
    i.read_message(&buf[..n], &mut out)?;
    let n = i.write_message(&[], &mut buf)?;
    r.read_message(&buf[..n], &mut out)?;
    assert!(i.is_handshake_finished() && r.is_handshake_finished());
    i.into_stateless_transport_mode()?;
    r.into_stateless_transport_mode()?;
    Ok(())
}

#[test]
fn xxpsk0_and_xxpsk3_handshakes_complete_with_snow() {
    let mesh = [7u8; 16];
    let psk = [9u8; 32];
    run(
        noise::session(&mesh, &psk, &key(1), true).unwrap(),
        noise::session(&mesh, &psk, &key(2), false).unwrap(),
    )
    .unwrap();
    run(
        noise::pairing(&psk, &key(3), true).unwrap(),
        noise::pairing(&psk, &key(4), false).unwrap(),
    )
    .unwrap();
}

#[test]
fn a_wrong_access_key_fails_at_message_one() {
    let mesh = [7u8; 16];
    let mut i = noise::session(&mesh, &[1u8; 32], &key(1), true).unwrap();
    let mut r = noise::session(&mesh, &[2u8; 32], &key(2), false).unwrap();
    let mut buf = vec![0u8; 1024];
    let mut out = vec![0u8; 1024];
    let n = i.write_message(&[], &mut buf).unwrap();
    assert!(r.read_message(&buf[..n], &mut out).is_err());
    // A different mesh id (prologue) fails the same way.
    let mut i = noise::session(&[1u8; 16], &[1u8; 32], &key(1), true).unwrap();
    let mut r = noise::session(&[2u8; 16], &[1u8; 32], &key(2), false).unwrap();
    let n = i.write_message(&[], &mut buf).unwrap();
    assert!(r.read_message(&buf[..n], &mut out).is_err());
}

#[test]
fn a_wrong_pairing_psk_fails_at_message_three() {
    let mut i = noise::pairing(&[1u8; 32], &key(1), true).unwrap();
    let mut r = noise::pairing(&[2u8; 32], &key(2), false).unwrap();
    let mut buf = vec![0u8; 1024];
    let mut out = vec![0u8; 1024];
    let n = i.write_message(&[], &mut buf).unwrap();
    r.read_message(&buf[..n], &mut out).unwrap();
    let n = r.write_message(&[], &mut buf).unwrap();
    i.read_message(&buf[..n], &mut out).unwrap();
    let n = i.write_message(&[], &mut buf).unwrap();
    assert!(r.read_message(&buf[..n], &mut out).is_err());
}
