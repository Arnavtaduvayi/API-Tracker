//! Point-to-point messages a session delivers (`proto::DirectMsg`). They are
//! never stored or relayed as items: `AccessKeyUpdate` (rotation),
//! `RollbackNotice` (the hold on minting) and `RightsRequest` (spend-cap
//! rebalancing, Increment 07).

use crate::error::NetResult;
use crate::node::MeshNode;
use api_tracker_core::mesh::caps;
use api_tracker_core::mesh::proto::DirectMsg;
use api_tracker_core::mesh::DeviceId;

/// What a session does with a direct message while it runs. An access key
/// is held back and applied by [`apply_access_key`] once the exchange's
/// commit is in, so the removal that justifies a rotation is known first.
pub fn handle(node: &MeshNode, peer: DeviceId, msg: DirectMsg) -> NetResult<Option<DirectMsg>> {
    match msg {
        msg @ DirectMsg::AccessKeyUpdate { .. } => Ok(Some(msg)),
        // Answered once the exchange committed, so the donor decides on
        // what the requester just sent (`apply_rights_request`).
        msg @ DirectMsg::RightsRequest { .. } => Ok(Some(msg)),
        // The peer holds this device's history past what it remembers
        // (PROTOCOL.md §7.4): every mint on this database waits until its
        // own items come back (`SqliteStore::hold_minting`), which the same
        // exchange normally does.
        DirectMsg::RollbackNotice { held_seq } => {
            node.store().hold_minting(peer, held_seq)?;
            Ok(None)
        }
    }
}

/// Apply an access key a peer delivered, after the exchange committed: store
/// it under the vault key if this device's roster justifies its epoch
/// (`membership::max_access_epoch`) and it is newer, or wins a tie (ADR 0031
/// R21). Returns whether the current key changed.
pub fn apply_access_key(node: &MeshNode, msg: DirectMsg) -> NetResult<bool> {
    let DirectMsg::AccessKeyUpdate { epoch, key } = msg else {
        return Ok(false);
    };
    let store = node.store();
    let max = api_tracker_core::mesh::membership::max_access_epoch(&store);
    Ok(node
        .vault()
        .accept_access_key(store.connection(), epoch, &key, max)?)
}

/// Answer a peer's rights request after the exchange committed
/// (`core::mesh::caps::grant`, through the escrow fence). Returns the
/// amount granted; the grant reaches the peer in a later exchange.
pub fn apply_rights_request(node: &MeshNode, peer: DeviceId, msg: DirectMsg) -> NetResult<u64> {
    let DirectMsg::RightsRequest {
        cap,
        month,
        want,
        reclaim,
    } = msg
    else {
        return Ok(0);
    };
    let ask = caps::RightsAsk {
        cap,
        month,
        want,
        reclaim,
    };
    let probe = node.gateway_probe();
    let mut store = node.store();
    Ok(caps::grant(
        &mut store,
        node.keys().signing_key(),
        &probe,
        &peer,
        ask,
    )?)
}

/// The rights requests to send `peer` at the start of an exchange.
pub fn rights_requests(node: &MeshNode, peer: DeviceId) -> NetResult<Vec<DirectMsg>> {
    let store = node.store();
    Ok(caps::rights_requests(&store, &peer)?
        .into_iter()
        .map(|a| DirectMsg::RightsRequest {
            cap: a.cap,
            month: a.month,
            want: a.want,
            reclaim: a.reclaim,
        })
        .collect())
}
