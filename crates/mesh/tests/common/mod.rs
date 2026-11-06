//! Shared harness: real vaults in temp directories, real `serve` loops on
//! `127.0.0.1:0`. No LAN, no mDNS, fake keys only.

#![allow(dead_code)]

use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, UnlockedVault, VaultPaths};
use api_tracker_mesh::pair::{self, JoinReport};
use api_tracker_mesh::serve::{bind_all, serve, ServeStats};
use api_tracker_mesh::{MeshNode, TransportLimits};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::thread::JoinHandle;
use std::time::Duration;
use tempfile::TempDir;

pub const MASTER: &str = "mesh-test-master-pw-01";

static FAST: Once = Once::new();

pub fn master() -> SecretString {
    SecretString::from(MASTER)
}

pub struct Dev {
    pub dir: TempDir,
    pub paths: VaultPaths,
    pub vault: UnlockedVault,
}

pub fn vault() -> Dev {
    FAST.call_once(|| std::env::set_var("API_TRACKER_INSECURE_FAST_KDF", "1"));
    let dir = TempDir::new().unwrap();
    let paths = VaultPaths::new(dir.path().join("data"));
    let vault = vault::create_vault(&paths, &master()).unwrap();
    Dev { dir, paths, vault }
}

pub fn genesis(name: &str) -> Dev {
    let d = vault();
    d.vault.mesh_init(name).unwrap();
    d
}

/// Limits for tests: the real bounds, a generous handshake rate (every test
/// connects from 127.0.0.1).
pub fn test_limits() -> TransportLimits {
    TransportLimits {
        handshakes_per_ip_per_minute: 1_000,
        ..TransportLimits::default()
    }
}

pub fn node(dev: &Dev) -> MeshNode {
    MeshNode::open(&dev.vault, Arc::new(SystemClock), test_limits()).unwrap()
}

pub struct Server {
    pub addr: SocketAddr,
    pub node: Arc<MeshNode>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Arc<ServeStats>>>,
}

impl Server {
    pub fn addr_string(&self) -> String {
        self.addr.to_string()
    }

    pub fn stop(mut self) -> Arc<ServeStats> {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.take().unwrap().join().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub fn serve_with(dev: &Dev, clock: Arc<dyn Clock>, limits: TransportLimits) -> Server {
    let node = Arc::new(MeshNode::open(&dev.vault, clock, limits).unwrap());
    let listeners = bind_all(&["127.0.0.1:0".parse().unwrap()], false).unwrap();
    let addr = listeners[0].local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (n, s) = (node.clone(), stop.clone());
    let handle =
        std::thread::spawn(move || serve(n, listeners, &|| s.load(Ordering::SeqCst)).unwrap());
    Server {
        addr,
        node,
        stop,
        handle: Some(handle),
    }
}

pub fn start(dev: &Dev) -> Server {
    serve_with(dev, Arc::new(SystemClock), test_limits())
}

pub fn invite(dev: &Dev, server: &Server) -> SecretString {
    let inv = dev.vault.mesh_invite_create(&master(), None).unwrap();
    api_tracker_core::mesh::invite::format_invite(&inv.token, &[server.addr_string()]).unwrap()
}

pub fn join(
    dev: &Dev,
    invite: &SecretString,
    name: &str,
) -> api_tracker_mesh::NetResult<JoinReport> {
    pair::join(
        &dev.vault,
        invite.expose(),
        name,
        Arc::new(SystemClock),
        test_limits(),
    )
}

/// A genesis serving, and a second device joined to it.
pub fn pair_of() -> (Dev, Server, Dev) {
    let a = genesis("dev-a");
    let server = start(&a);
    let b = vault();
    let inv = invite(&a, &server);
    let r = join(&b, &inv, "dev-b").unwrap();
    assert!(r.exchange.aborted.is_none(), "{:?}", r.exchange);
    (a, server, b)
}

pub fn wait_until(mut f: impl FnMut() -> bool, what: &str) {
    for _ in 0..200 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

/// Wait up to `secs` for `f`.
pub fn wait_for(secs: u64, mut f: impl FnMut() -> bool, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out after {secs} s waiting for {what}");
}

/// A node config for tests: 127.0.0.1:0, a short interval, a fixed jitter
/// seed, no discovery.
pub fn node_config(interval_ms: u64) -> api_tracker_mesh::runtime::NodeConfig {
    let mut cfg = api_tracker_mesh::runtime::NodeConfig::new(vec!["127.0.0.1:0".parse().unwrap()]);
    cfg.interval = Duration::from_millis(interval_ms);
    cfg.jitter = api_tracker_mesh::peers::Jitter::new(0x5eed);
    cfg
}

/// Start the full node runtime for `dev`.
pub fn run_node(
    dev: &Dev,
    cfg: api_tracker_mesh::runtime::NodeConfig,
    clock: Arc<dyn Clock>,
    stop: Box<dyn api_tracker_mesh::runtime::StopCondition>,
) -> api_tracker_mesh::runtime::RunningNode {
    let node = MeshNode::open(&dev.vault, clock, test_limits()).unwrap();
    api_tracker_mesh::runtime::RunningNode::start(node, &dev.paths.data_dir, cfg, stop).unwrap()
}

/// This device's name as `other` sees it.
pub fn name_seen_by(other: &Dev, of: &Dev) -> Option<String> {
    let id = of.vault.mesh_status().unwrap().detail.unwrap().device_id;
    other
        .vault
        .mesh_devices()
        .unwrap()
        .into_iter()
        .find(|d| d.device_id == id)
        .and_then(|d| d.name)
}

pub fn device_id(dev: &Dev) -> api_tracker_core::mesh::DeviceId {
    dev.vault.mesh_status().unwrap().detail.unwrap().device_id
}

/// Join `dev` to the mesh through `inviter`'s running node at `addr`.
pub fn join_via(inviter: &Dev, addr: &str, dev: &Dev, name: &str) {
    let inv = inviter.vault.mesh_invite_create(&master(), None).unwrap();
    let text =
        api_tracker_core::mesh::invite::format_invite(&inv.token, &[addr.to_owned()]).unwrap();
    let r = join(dev, &text, name).unwrap();
    assert!(r.exchange.aborted.is_none(), "{:?}", r.exchange);
}
