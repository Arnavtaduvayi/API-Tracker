//! Member-session handshakes over TCP (PROTOCOL.md §9, MESH-SI-2).
//!
//! The initiator sends the session preamble and runs `XXpsk0` with its
//! current access key. The responder tries its current access key on message
//! 1, then the previous one while it is in its 30-day grace period. With psk0
//! a prober without a key fails at message 1, before the responder has sent
//! anything. Each side then checks the other's static key against the
//! **active** roster: the initiator before it sends message 3, the responder
//! after reading it. No frame moves before both checks pass.

use crate::error::{NetError, NetResult};
use crate::node::MeshNode;
use crate::noise;
use crate::wire::{self, Preamble, MAX_HANDSHAKE_MSG};
use api_tracker_core::mesh::invite::AccessKey;
use api_tracker_core::mesh::DeviceId;
use snow::{HandshakeState, StatelessTransportState};
use std::net::TcpStream;

fn send(stream: &mut TcpStream, hs: &mut HandshakeState) -> NetResult<()> {
    let mut buf = [0u8; MAX_HANDSHAKE_MSG];
    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|_| NetError::Handshake("could not write a handshake message"))?;
    wire::write_msg(stream, &buf[..n])?;
    Ok(())
}

fn recv(stream: &mut TcpStream, hs: &mut HandshakeState) -> NetResult<()> {
    let msg = wire::read_msg(stream, MAX_HANDSHAKE_MSG)?;
    let mut payload = [0u8; MAX_HANDSHAKE_MSG];
    hs.read_message(&msg, &mut payload)
        .map_err(|_| NetError::Handshake("wrong mesh or access key"))?;
    Ok(())
}

fn finish(hs: HandshakeState) -> NetResult<StatelessTransportState> {
    hs.into_stateless_transport_mode()
        .map_err(|_| NetError::Handshake("the handshake did not finish"))
}

/// Dial side: returns the channel and the authenticated peer.
pub fn initiate(
    stream: &mut TcpStream,
    node: &MeshNode,
    access_key: &AccessKey,
) -> NetResult<(StatelessTransportState, DeviceId)> {
    stream.set_read_timeout(Some(node.limits().handshake_timeout))?;
    stream.set_write_timeout(Some(node.limits().handshake_timeout))?;
    wire::write_preamble(stream, Preamble::Session)?;
    let mesh = *node.mesh_id().as_bytes();
    let mut hs = noise::session(
        &mesh,
        access_key.expose(),
        node.keys().expose_noise_secret(),
        true,
    )
    .map_err(|_| NetError::Handshake("could not start the handshake"))?;
    send(stream, &mut hs)?;
    recv(stream, &mut hs)?;
    let remote = hs
        .get_remote_static()
        .ok_or(NetError::Handshake("the peer sent no static key"))?;
    let Some(peer) = node.active_device(remote) else {
        return Err(NetError::Refused(
            "the peer is not an active member of this mesh",
        ));
    };
    send(stream, &mut hs)?;
    Ok((finish(hs)?, peer))
}

/// Answer side, after the session preamble was read.
pub fn respond(
    stream: &mut TcpStream,
    node: &MeshNode,
) -> NetResult<(StatelessTransportState, DeviceId)> {
    let msg1 = wire::read_msg(stream, MAX_HANDSHAKE_MSG)?;
    let keys = node.access_keys()?;
    let mesh = *node.mesh_id().as_bytes();
    let mut payload = [0u8; MAX_HANDSHAKE_MSG];
    let mut chosen = None;
    for (_, key) in std::iter::once(&keys.current).chain(keys.previous.as_ref()) {
        let mut hs = noise::session(
            &mesh,
            key.expose(),
            node.keys().expose_noise_secret(),
            false,
        )
        .map_err(|_| NetError::Handshake("could not start the handshake"))?;
        if hs.read_message(&msg1, &mut payload).is_ok() {
            chosen = Some(hs);
            break;
        }
    }
    let mut hs = chosen.ok_or(NetError::Handshake("wrong mesh or access key"))?;
    send(stream, &mut hs)?;
    recv(stream, &mut hs)?;
    let remote = hs
        .get_remote_static()
        .ok_or(NetError::Handshake("the peer sent no static key"))?;
    let Some(peer) = node.active_device(remote) else {
        return Err(NetError::Refused(
            "the peer is not an active member of this mesh",
        ));
    };
    Ok((finish(hs)?, peer))
}
