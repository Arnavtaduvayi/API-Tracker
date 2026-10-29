//! The round hooks a node runs before each round ([`crate::runtime::RoundHook`]):
//! the usage publisher (Increment 06), then the spend-cap reconciler
//! (Increment 07), so caps see this round's usage.

use crate::error::{NetError, NetResult};
use crate::node::MeshNode;
use crate::runtime::RoundHook;
use api_tracker_core::mesh::MeshError;
use api_tracker_core::mesh::{caps, publish};
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

/// Runs the spend-cap reconciler (`core::mesh::caps::reconcile`): this
/// device's `cap.used`, escrowed transfers, the owner's monthly and
/// advance minting and distribution, and burns after a lower.
pub struct CapReconciler;

impl RoundHook for CapReconciler {
    fn name(&self) -> &'static str {
        "cap reconciler"
    }

    fn before_round(&self, node: &MeshNode) -> NetResult<()> {
        let probe = node.gateway_probe();
        let mut store = node.store();
        match caps::reconcile(&mut store, node.keys().signing_key(), &probe) {
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
    vec![
        std::sync::Arc::new(UsagePublisher),
        std::sync::Arc::new(CapReconciler),
    ]
}
