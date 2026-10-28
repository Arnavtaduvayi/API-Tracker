//! The state every connection shares: the store, the keys, the vault
//! capability, the clock and the limits. `serve`, `replicate` and pairing use
//! it; the Increment 05 node loop extends it.

use crate::error::NetResult;
use api_tracker_core::mesh::clock::Clock;
use api_tracker_core::mesh::identity::{self, MeshKeys};
use api_tracker_core::mesh::membership::{AccessKeys, MeshVault};
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::{DeviceId, MeshId};
use api_tracker_core::vault::UnlockedVault;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// Transport bounds (DESIGN §D12, MESH-SI-8). Tests shorten them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportLimits {
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_session: Duration,
    pub max_sessions: usize,
    pub handshakes_per_ip_per_minute: u32,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            max_session: Duration::from_secs(600),
            max_sessions: 8,
            handshakes_per_ip_per_minute: 10,
        }
    }
}

pub struct MeshNode {
    store: Mutex<SqliteStore>,
    keys: MeshKeys,
    vault: MeshVault,
    clock: Arc<dyn Clock>,
    limits: TransportLimits,
}

impl MeshNode {
    /// A node for this vault's mesh identity. Refuses a copied, rolled-back
    /// or forked identity (`identity::preflight`, MESH-SI-5).
    pub fn open(
        vault: &UnlockedVault,
        clock: Arc<dyn Clock>,
        limits: TransportLimits,
    ) -> NetResult<Self> {
        let store = vault.mesh_open_store()?;
        identity::preflight(&store)?;
        Ok(Self {
            store: Mutex::new(store),
            keys: vault.mesh_keys()?,
            vault: vault.mesh_vault(),
            clock,
            limits,
        })
    }

    /// The store, for one short operation, refreshed if another process
    /// (a CLI command, say) wrote since. A panic elsewhere never leaves it
    /// unusable: every store write either commits or reloads from disk.
    pub fn store(&self) -> MutexGuard<'_, SqliteStore> {
        let mut guard = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        // A failed refresh keeps the last good mirror; the next write
        // transaction re-checks the generation itself.
        let _ = guard.refresh();
        guard
    }

    pub fn keys(&self) -> &MeshKeys {
        &self.keys
    }

    pub fn vault(&self) -> &MeshVault {
        &self.vault
    }

    pub fn limits(&self) -> TransportLimits {
        self.limits
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub fn mesh_id(&self) -> MeshId {
        self.keys.mesh_id()
    }

    pub fn self_id(&self) -> DeviceId {
        self.keys.device_id()
    }

    pub fn access_keys(&self) -> NetResult<AccessKeys> {
        let now = self.clock.now_ms();
        Ok(self.vault.access_keys(self.store().connection(), now)?)
    }

    /// The active roster device whose Noise key is `remote` (MESH-SI-2).
    pub fn active_device(&self, remote: &[u8]) -> Option<DeviceId> {
        let store = self.store();
        let roster = &store.state().roster;
        let found = roster
            .known()
            .find(|(d, k)| k.noise_pub.0.as_slice() == remote && roster.is_active(d))
            .map(|(d, _)| *d);
        found.filter(|d| *d != self.self_id())
    }
}
