//! Point-to-point messages a session delivers (`proto::DirectMsg`). They are
//! never stored or relayed as items: `AccessKeyUpdate` (rotation) and
//! `RollbackNotice` (the hold on minting). This is the dispatch point later
//! increments extend (Increment 07: `RightsRequest`).

use crate::error::NetResult;
use crate::node::MeshNode;
use api_tracker_core::mesh::proto::DirectMsg;
use api_tracker_core::mesh::DeviceId;

/// What a session does with a direct message while it runs. An access key
/// is held back and applied by [`apply_access_key`] once the exchange's
/// commit is in, so the removal that justifies a rotation is known first.
pub fn handle(node: &MeshNode, peer: DeviceId, msg: DirectMsg) -> NetResult<Option<DirectMsg>> {
    match msg {
        msg @ DirectMsg::AccessKeyUpdate { .. } => Ok(Some(msg)),
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
