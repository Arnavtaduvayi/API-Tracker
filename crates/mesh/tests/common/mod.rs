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
