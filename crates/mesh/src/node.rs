//! The state every connection shares: the store, the keys, the vault
//! capability, the clock, the limits and the session slots. `serve`,
//! `replicate`, pairing and the node runtime ([`crate::runtime`]) use it.
//!
//! The keys live here and nowhere else in the crate: when the last
//! `Arc<MeshNode>` drops (the runtime joins every thread that holds one
//! before it reports a stop), [`MeshKeys`] and [`MeshVault`] zeroize
//! (MESH-SI-7).

use crate::error::NetResult;
use api_tracker_core::mesh::clock::Clock;
use api_tracker_core::mesh::identity::{self, MeshKeys};
use api_tracker_core::mesh::membership::{AccessKeys, MeshVault};
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::{DeviceId, MeshId};
use api_tracker_core::vault::UnlockedVault;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
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
    data_dir: PathBuf,
    keys: MeshKeys,
    vault: MeshVault,
    clock: Arc<dyn Clock>,
    limits: TransportLimits,
    sessions: Arc<AtomicUsize>,
}

/// One of the node's `max_sessions` session slots (inbound and outbound
/// together, DESIGN §D12); released on drop.
pub struct SessionSlot(Arc<AtomicUsize>);

impl Drop for SessionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
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
            data_dir: vault.paths().data_dir.clone(),
            keys: vault.mesh_keys()?,
            vault: vault.mesh_vault(),
            clock,
            limits,
            sessions: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Take a session slot, or `None` when `max_sessions` exchanges (in and
    /// out together) are already running.
    pub fn try_session(&self) -> Option<SessionSlot> {
        let max = self.limits.max_sessions;
        let mut cur = self.sessions.load(Ordering::SeqCst);
        loop {
            if cur >= max {
                return None;
            }
            match self.sessions.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Some(SessionSlot(self.sessions.clone())),
                Err(actual) => cur = actual,
            }
        }
    }

    /// Exchanges running now, in and out.
    pub fn active_sessions(&self) -> usize {
        self.sessions.load(Ordering::SeqCst)
    }

    /// The session counter alone (for status readers that must not hold
    /// the node, and so its keys).
    pub fn session_counter(&self) -> Arc<AtomicUsize> {
        self.sessions.clone()
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

    /// The data directory this node's identity belongs to.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Whether this data directory's gateway is running, for the spend-cap
    /// escrow fence (MESH-SI-10).
    pub fn gateway_probe(&self) -> GatewaySocket {
        let port = api_tracker_core::mesh::caps::escrow::gateway_port(self.store().connection())
            .ok()
            .flatten();
        GatewaySocket::new(self.data_dir.clone(), port)
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

/// The gateway's liveness for the escrow fence, consulted only while cap
/// enforcement is on. On Unix, the way the gateway decides it
/// (`gateway::control::instance_is_live`): a connection to its control
/// socket, `<data-dir>/gateway.sock`, rather than a pid file. Elsewhere (no
/// control channel), a loopback connection to its configured port: nothing
/// listening proves it is not running; anything listening counts as
/// running, the conservative answer (a transfer then waits for the
/// gateway's acknowledgement).
pub struct GatewaySocket {
    dir: PathBuf,
    port: Option<u16>,
}

impl GatewaySocket {
    pub fn new(dir: PathBuf, port: Option<u16>) -> Self {
        Self { dir, port }
    }
}

impl api_tracker_core::mesh::caps::GatewayProbe for GatewaySocket {
    fn gateway_running(&self) -> bool {
        #[cfg(unix)]
        {
            let _ = self.port;
            std::os::unix::net::UnixStream::connect(self.dir.join("gateway.sock")).is_ok()
        }
        #[cfg(not(unix))]
        {
            let _ = &self.dir;
            self.port.is_some_and(|p| {
                std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], p)),
                    Duration::from_millis(300),
                )
                .is_ok()
            })
        }
    }
}
