//! The round hooks a node runs before each round ([`crate::runtime::RoundHook`]).
//! Increment 06: the usage publisher. Increment 07 adds the cap reconciler
//! after it, so caps see this round's usage.

use crate::error::{NetError, NetResult};
use crate::node::MeshNode;
use crate::runtime::RoundHook;
use api_tracker_core::mesh::publish;
use api_tracker_core::mesh::MeshError;
use api_tracker_core::CoreError;

/// Publishes this device's gateway usage for bound projects
/// (`core::mesh::publish`). A refused mint (rollback hold, untrusted
/// identity) is "not now", not an error.
pub struct UsagePublisher;

impl RoundHook for UsagePublisher {
    fn name(&self) -> &'static str {
        "usage publisher"
    }

    fn before_round(&self, node: &MeshNode) -> NetResult<()> {
        let now = node.clock().now_ms();
        let mut store = node.store();
        match publish::publish(&mut store, node.keys().signing_key(), now) {
            Ok(_) => Ok(()),
            Err(CoreError::Mesh(
                MeshError::RollbackHold | MeshError::IdentityMismatch(_) | MeshError::Forked,
            )) => Ok(()),
            Err(e) => Err(NetError::Core(e)),
        }
    }
}

/// The hooks every node runs, in order.
pub fn default_hooks() -> Vec<std::sync::Arc<dyn RoundHook>> {
    vec![std::sync::Arc::new(UsagePublisher)]
}
