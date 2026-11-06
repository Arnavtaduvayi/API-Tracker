//! Pairing (DESIGN §D10, PROTOCOL.md §9): a new device joins with a one-time
//! invite.
//!
//! The joiner dials an address from the invite and sends the pairing
//! preamble with the invite's **hint**. The inviter answers only if a live
//! invite matches the hint, so its static key is not shown to every prober.
//! They run `XXpsk3` with the psk derived from the token: the joiner proves
//! it holds the token in message 3, and the inviter proves it with its first
//! encrypted frame. Inside the channel the joiner sends `PairRequest` (its
//! public keys and name, its Noise key bound to the handshake). The inviter
//! claims the invite (single use, recorded before it replies), mints the
//! joiner's `roster.add`, and replies `PairAccept`. A normal exchange then
//! runs on the same connection.

use crate::error::{NetError, NetResult};
use crate::node::{MeshNode, TransportLimits};
use crate::noise;
use crate::session::{exchange, Direction, ExchangeReport};
use crate::wire::{self, Deadline, Preamble, MAX_HANDSHAKE_MSG};
use api_tracker_core::mesh::clock::Clock;
use api_tracker_core::mesh::identity::{self, MeshSelfInfo};
use api_tracker_core::mesh::invite::{parse_invite, PairAccept, PairRequest, HINT_LEN};
use api_tracker_core::mesh::membership::{self, PendingIdentity};
use api_tracker_core::mesh::sign::PublicKeyBytes;
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::{DeviceId, MeshError};
use api_tracker_core::vault::UnlockedVault;
use api_tracker_core::CoreError;
use serde::{Deserialize, Serialize};
use snow::HandshakeState;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Instant;

/// The largest pairing message (`PairRequest`/the reply); far above need.
const MAX_PAIR_FRAME: usize = 16 * 1024;

/// Why an inviter refused. Only these texts ever cross the wire; a joiner
/// shows nothing else, so a peer cannot put words in its output.
const REFUSALS: &[&str] = &[
    "it is unknown",
    "it was already used",
    "it has expired",
    "it had too many failed attempts",
    "the joiner's key does not match its handshake",
    "the device name is not valid",
    "the inviter could not add this device",
];

#[derive(Serialize, Deserialize)]
#[serde(tag = "t", deny_unknown_fields)]
enum PairReply {
    Accepted { accept: PairAccept },
    Refused { reason: String },
}

fn refusal(e: &CoreError) -> &'static str {
    match e {
        CoreError::Mesh(MeshError::InviteRefused(s)) => REFUSALS
            .iter()
            .find(|r| *r == s)
            .copied()
            .unwrap_or(REFUSALS[6]),
        CoreError::Mesh(MeshError::InvalidDeviceName) => REFUSALS[5],
        _ => REFUSALS[6],
    }
}

fn hs_send(stream: &mut Deadline<'_>, hs: &mut HandshakeState) -> NetResult<()> {
    let mut buf = [0u8; MAX_HANDSHAKE_MSG];
    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|_| NetError::Handshake("could not write a handshake message"))?;
    wire::write_msg(stream, &buf[..n])?;
    Ok(())
}

/// Read one handshake message. A failure to read it (a timeout, a reset, a
/// message over the cap) is an `Io` error; a message that does not
/// authenticate under the psk is `Handshake`. Only the second is a wrong
/// attempt at the invite (audit MP-11).
fn hs_recv(stream: &mut Deadline<'_>, hs: &mut HandshakeState) -> NetResult<()> {
    let msg = wire::read_msg(stream, MAX_HANDSHAKE_MSG)?;
    let mut payload = [0u8; MAX_HANDSHAKE_MSG];
    hs.read_message(&msg, &mut payload)
        .map_err(|_| NetError::Handshake("wrong invite"))?;
    Ok(())
}

/// What `mesh join` did.
#[derive(Debug, Serialize)]
pub struct JoinReport {
    pub info: MeshSelfInfo,
    pub exchange: ExchangeReport,
    /// After the first exchange: the inviter's roster entry carries the Noise
    /// key that answered the pairing handshake. Always `true` in a report: a
    /// join where it does not hold fails and keeps no identity (audit
    /// MP-12).
    pub inviter_verified: bool,
}

/// Join the mesh an invite names (the joiner's side).
pub fn join(
    vault: &UnlockedVault,
    invite: &str,
    name: &str,
    clock: Arc<dyn Clock>,
    limits: TransportLimits,
) -> NetResult<JoinReport> {
    let (token, addrs) = parse_invite(invite)?;
    if identity::self_info(vault.connection())?.is_some() {
        return Err(MeshError::AlreadyInMesh.into());
    }
    let pending = PendingIdentity::generate(name)?;
    let psk = token.pairing_psk();
    let hint = token.hint();
    drop(token);
    let mut last = NetError::Io(std::io::ErrorKind::NotFound);
    // Every address in the invite, and every address each one resolves to.
    // A failure on the way (nothing listening, a different service, a
    // handshake that does not complete) moves on to the next; a refusal from
    // the inviter, or a malformed reply, ends the attempt.
    let socks: Vec<(&String, std::net::SocketAddr)> = addrs
        .iter()
        .filter_map(|a| a.to_socket_addrs().ok().map(|s| s.map(move |x| (a, x))))
        .flatten()
        .collect();
    for (addr, sock) in socks {
        let (reader, writer, remote, reply) = match attempt(sock, hint, &psk, &pending, limits) {
            Ok(r) => r,
            Err(e @ (NetError::Io(_) | NetError::Handshake(_) | NetError::Refused(_))) => {
                last = e;
                continue;
            }
            Err(e) => return Err(e),
        };
        let accept = match reply {
            PairReply::Accepted { accept } => accept,
            PairReply::Refused { reason } => {
                let known = REFUSALS
                    .iter()
                    .find(|r| **r == reason)
                    .copied()
                    .unwrap_or("the inviter refused");
                return Err(MeshError::InviteRefused(known).into());
            }
        };
        let info = vault.mesh_join(&pending, &accept)?;
        let node = match MeshNode::open(vault, clock, limits) {
            Ok(node) => node,
            Err(e) => {
                forget_identity(vault);
                return Err(e);
            }
        };
        let report = exchange(&node, reader, writer, accept.inviter, Direction::Outbound);
        // The inviter is who the roster says only if its roster entry, as
        // the exchange delivered it, carries the Noise key that answered the
        // pairing handshake. Otherwise whoever answered held the invite token
        // but not the inviter's identity: keep nothing (audit MP-12).
        let inviter_verified = node
            .store()
            .state()
            .roster
            .keys(&accept.inviter)
            .is_some_and(|k| k.noise_pub.0.as_slice() == remote.as_slice());
        if !inviter_verified {
            let why = if report.aborted.is_some() {
                // Nothing to verify the inviter against: fail closed.
                "the first exchange with the inviter did not complete; pair again"
            } else {
                "the inviter's key does not match its roster entry"
            };
            drop(node);
            forget_identity(vault);
            return Err(NetError::Refused(why));
        }
        crate::replicate::log(&node, &report);
        // The invite's address that answered becomes this device's first
        // peer (the user entered it, with the invite), so a node started
        // next has someone to dial even before any device published an
        // address. Best effort: joining succeeded either way.
        if let Ok((addr, _)) = vault.mesh_peer_add(addr) {
            let store = node.store();
            let _ = api_tracker_core::mesh::peers::record_attempt(
                store.connection(),
                &addr,
                node.clock().now_ms(),
                api_tracker_core::mesh::peers::AttemptOutcome::Reached(accept.inviter),
            );
        }
        return Ok(JoinReport {
            info,
            exchange: report,
            inviter_verified,
        });
    }
    Err(last)
}

/// Undo a join that cannot stand: the same local wipe as `mesh leave`
/// (identity, mesh tables, marker). Nothing was minted under the new
/// identity but its roster.add, which the inviter minted; the keys behind it
/// are gone. Best effort: the join fails either way.
fn forget_identity(vault: &UnlockedVault) {
    let _ = identity::leave_local_wipe(vault.connection(), &vault.paths().data_dir);
}

type PairChannel = (wire::FrameReader, wire::FrameWriter, Vec<u8>, PairReply);

/// One pairing attempt at one address, up to the inviter's reply.
fn attempt(
    sock: std::net::SocketAddr,
    hint: [u8; HINT_LEN],
    psk: &[u8; 32],
    pending: &PendingIdentity,
    limits: TransportLimits,
) -> NetResult<PairChannel> {
    let stream = TcpStream::connect_timeout(&sock, limits.handshake_timeout)?;
    // The handshake and the inviter's reply finish within one handshake
    // timeout, however the inviter paces its bytes (audit MP-4).
    let until = Instant::now() + limits.handshake_timeout;
    let (remote, state) = {
        let mut d = Deadline::new(&stream, until);
        wire::write_preamble(&mut d, Preamble::Pair { hint })?;
        let mut hs = noise::pairing(psk, pending.expose_noise_secret(), true)
            .map_err(|_| NetError::Handshake("could not start the handshake"))?;
        hs_send(&mut d, &mut hs)?;
        hs_recv(&mut d, &mut hs)?;
        hs_send(&mut d, &mut hs)?;
        let remote = hs
            .get_remote_static()
            .ok_or(NetError::Handshake("the inviter sent no static key"))?
            .to_vec();
        let state = hs
            .into_stateless_transport_mode()
            .map_err(|_| NetError::Handshake("the handshake did not finish"))?;
        (remote, state)
    };
    stream.set_read_timeout(Some(limits.handshake_timeout))?;
    stream.set_write_timeout(Some(limits.handshake_timeout))?;
    let (mut reader, mut writer) = wire::split(stream, state)?;
    let req = serde_json::to_vec(&pending.request())
        .map_err(|_| NetError::Session("a frame did not encode"))?;
    writer.send(&req)?;
    // The inviter's first encrypted frame is what proves it holds the token:
    // a wrong psk fails to decrypt here.
    reader.set_deadline(Some(until));
    let reply = reader.recv().map_err(|e| match e.kind() {
        std::io::ErrorKind::InvalidData => NetError::Handshake("wrong invite"),
        _ => NetError::Refused("the inviter closed the connection"),
    })?;
    reader.set_deadline(None);
    if reply.len() > MAX_PAIR_FRAME {
        return Err(NetError::Session("a malformed frame"));
    }
    let reply: PairReply =
        serde_json::from_slice(&reply).map_err(|_| NetError::Session("a malformed frame"))?;
    Ok((reader, writer, remote, reply))
}

/// The inviter's side, after a pairing preamble with `hint` was read.
/// Returns the new member and the channel, for the exchange that follows.
/// The handshake and the joiner's request finish by `until`, the deadline
/// the preamble was read under (audit MP-4).
pub(crate) fn respond(
    stream: &mut TcpStream,
    node: &MeshNode,
    hint: [u8; HINT_LEN],
    until: Instant,
) -> NetResult<(DeviceId, wire::FrameReader, wire::FrameWriter)> {
    let candidates = {
        let store = node.store();
        node.vault().invite_candidates(store.connection(), &hint)?
    };
    // No live invite matches: answer nothing, reveal nothing.
    let Some(invite) = candidates.into_iter().next() else {
        return Err(NetError::Refused("no live invite matches"));
    };
    let (remote, state) = {
        let mut d = Deadline::new(stream, until);
        let msg1 = wire::read_msg(&mut d, MAX_HANDSHAKE_MSG)?;
        let mut hs = noise::pairing(&invite.psk, node.keys().expose_noise_secret(), false)
            .map_err(|_| NetError::Handshake("could not start the handshake"))?;
        let mut payload = [0u8; MAX_HANDSHAKE_MSG];
        hs.read_message(&msg1, &mut payload)
            .map_err(|_| NetError::Handshake("a malformed handshake message"))?;
        hs_send(&mut d, &mut hs)?;
        match hs_recv(&mut d, &mut hs) {
            Ok(()) => {}
            // Message 3 arrived and does not authenticate under this
            // invite's psk: a wrong token, one of the five attempts.
            Err(NetError::Handshake(_)) => {
                let store = node.store();
                membership::record_failed_attempt(store.connection(), &invite.token_hash)?;
                return Err(NetError::Handshake("wrong invite token"));
            }
            // A timeout, a reset or an oversize message is no proof of a
            // wrong token: it costs the invite nothing (audit MP-11).
            Err(e) => return Err(e),
        }
        let remote = PublicKeyBytes(
            hs.get_remote_static()
                .and_then(|k| <[u8; 32]>::try_from(k).ok())
                .ok_or(NetError::Handshake("the joiner sent no static key"))?,
        );
        let state = hs
            .into_stateless_transport_mode()
            .map_err(|_| NetError::Handshake("the handshake did not finish"))?;
        (remote, state)
    };
    stream.set_read_timeout(Some(node.limits().handshake_timeout))?;
    stream.set_write_timeout(Some(node.limits().handshake_timeout))?;
    let (mut reader, mut writer) = wire::split(stream.try_clone()?, state)?;
    reader.set_deadline(Some(until));
    let bytes = reader
        .recv()
        .map_err(|_| NetError::Session("the joiner closed the connection"))?;
    reader.set_deadline(None);
    if bytes.len() > MAX_PAIR_FRAME {
        return Err(NetError::Session("a malformed frame"));
    }
    let req: PairRequest =
        serde_json::from_slice(&bytes).map_err(|_| NetError::Session("a malformed frame"))?;
    let current = node.access_keys()?.current;
    let accepted = {
        let mut store = node.store();
        membership::accept_pairing(
            &mut store,
            node.keys().signing_key(),
            &invite.token_hash,
            &req,
            &remote,
            &current,
        )
    };
    let (reply, outcome) = match accepted {
        Ok(accept) => {
            let joiner = api_tracker_core::mesh::sign::derive_device_id(
                &req.sign_pub,
                &req.noise_pub,
                &req.seal_pub,
            );
            (PairReply::Accepted { accept }, Ok(joiner))
        }
        Err(e) => {
            let reason = refusal(&e);
            (
                PairReply::Refused {
                    reason: reason.to_owned(),
                },
                Err(NetError::Refused(reason)),
            )
        }
    };
    let bytes =
        serde_json::to_vec(&reply).map_err(|_| NetError::Session("a frame did not encode"))?;
    writer.send(&bytes)?;
    Ok((outcome?, reader, writer))
}
