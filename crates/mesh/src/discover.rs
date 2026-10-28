//! Opt-in LAN discovery (`tethra mesh serve --discover`, DESIGN §D13).
//!
//! A node that discovers announces `_tethra-mesh._tcp.local.` and browses for
//! it. What it announces reveals as little as possible:
//! - the TXT record holds only `v=1` and `m=` the first 16 hex characters of
//!   `BLAKE3-keyed(access_key, "mdns" || <UTC day>)`: members of the mesh
//!   recognise it, anyone else sees a value that changes every day and links
//!   to nothing;
//! - the instance and host names are random per boot: no device, user or
//!   host name;
//! - the port is the listen port, the addresses the listen addresses.
//!
//! Discovery only suggests addresses. Every connection still runs the
//! authenticated handshake against the roster (MESH-SI-2), so a forged
//! announcement can waste a dial, never admit a device. mDNS is multicast on
//! the local link: it does not cross routers or VPNs (use `peer add` there).
//!
//! [`MdnsDiscovery`] uses `mdns-sd` (no async runtime). Tests and CI use
//! [`FakeDiscovery`], an in-memory registry shared by test nodes, and never
//! multicast; `tests/discover.rs` fails if a test constructs the real one.

use crate::error::{NetError, NetResult};
use api_tracker_core::mesh::kinds::Day;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

/// The DNS-SD service type.
pub const SERVICE: &str = "_tethra-mesh._tcp.local.";
const DAY_MS: u64 = 86_400_000;

/// One announcement seen on the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub addrs: Vec<SocketAddr>,
    pub txt: BTreeMap<String, String>,
}

pub trait Discovery: Send + Sync {
    /// Announce this node (replacing an earlier announcement).
    fn announce(&self, port: u16, ips: &[IpAddr], txt: &BTreeMap<String, String>) -> NetResult<()>;
    /// What other nodes announce now (never this node's own announcement).
    fn browse(&self) -> Vec<Sighting>;
}

/// The mesh tag for one UTC day: 16 hex characters of a keyed BLAKE3 hash.
pub fn tag(access_key: &[u8; 32], day: Day) -> String {
    let mut input = b"mdns".to_vec();
    input.extend_from_slice(day.to_string().as_bytes());
    blake3::keyed_hash(access_key, &input).to_hex()[..16].to_owned()
}

/// The TXT record to announce at `now_ms`: `v` and `m`, nothing else.
pub fn txt(access_key: &[u8; 32], now_ms: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("v".to_owned(), "1".to_owned()),
        ("m".to_owned(), tag(access_key, Day::from_unix_ms(now_ms))),
    ])
}

/// Whether an announcement is this mesh's: version 1 and a tag made with one
/// of `keys` for the UTC day of `now_ms` or the day either side of it
/// (devices whose clocks straddle midnight).
pub fn recognises(sighting: &Sighting, keys: &[&[u8; 32]], now_ms: u64) -> bool {
    if sighting.txt.get("v").map(String::as_str) != Some("1") {
        return false;
    }
    let Some(m) = sighting.txt.get("m") else {
        return false;
    };
    let days = [
        now_ms.saturating_sub(DAY_MS),
        now_ms,
        now_ms.saturating_add(DAY_MS),
    ];
    keys.iter().any(|k| {
        days.iter().any(|d| {
            let t = tag(k, Day::from_unix_ms(*d));
            blake3::hash(t.as_bytes()) == blake3::hash(m.as_bytes())
        })
    })
}

/// A random name, fresh per boot.
pub fn random_name(prefix: &str) -> String {
    let b = api_tracker_core::crypto::random_bytes(8);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{prefix}{hex}")
}

// ------------------------------------------------------------------ fake

#[derive(Default)]
struct Registry {
    entries: HashMap<String, Sighting>,
}

/// An in-memory "network" that test nodes share: each handle announces under
/// its own random instance name and browses everyone else's.
#[derive(Clone)]
pub struct FakeDiscovery {
    net: Arc<Mutex<Registry>>,
    instance: String,
}

impl FakeDiscovery {
    /// A new, empty network.
    pub fn network() -> Self {
        Self {
            net: Arc::new(Mutex::new(Registry::default())),
            instance: random_name("fake-"),
        }
    }

    /// Another node's handle on the same network.
    pub fn join(&self) -> Self {
        Self {
            net: self.net.clone(),
            instance: random_name("fake-"),
        }
    }

    /// Put an arbitrary announcement on the network (a stranger's, say).
    pub fn inject(&self, name: &str, sighting: Sighting) {
        self.net
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .insert(name.to_owned(), sighting);
    }

    /// What this handle announced (tests inspect the TXT record).
    pub fn announced(&self) -> Option<Sighting> {
        self.net
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .get(&self.instance)
            .cloned()
    }

    pub fn instance_name(&self) -> &str {
        &self.instance
    }
}

impl Discovery for FakeDiscovery {
    fn announce(&self, port: u16, ips: &[IpAddr], txt: &BTreeMap<String, String>) -> NetResult<()> {
        let s = Sighting {
            addrs: ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect(),
            txt: txt.clone(),
        };
        self.inject(&self.instance.clone(), s);
        Ok(())
    }

    fn browse(&self) -> Vec<Sighting> {
        let reg = self.net.lock().unwrap_or_else(PoisonError::into_inner);
        reg.entries
            .iter()
            .filter(|(k, _)| **k != self.instance)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

// ------------------------------------------------------------------ mDNS

/// Multicast DNS-SD on the local link (`mdns-sd`). Constructed only by
/// `serve --discover`; never in tests.
pub struct MdnsDiscovery {
    daemon: mdns_sd::ServiceDaemon,
    instance: String,
    host: String,
    registered: Mutex<Option<String>>,
    seen: Arc<Mutex<BTreeMap<String, Sighting>>>,
}

impl MdnsDiscovery {
    pub fn new() -> NetResult<Self> {
        let daemon = mdns_sd::ServiceDaemon::new()
            .map_err(|_| NetError::Node("mDNS discovery could not start"))?;
        let rx = daemon
            .browse(SERVICE)
            .map_err(|_| NetError::Node("mDNS discovery could not browse"))?;
        let instance = random_name("tethra-");
        let own_fullname = format!("{instance}.{SERVICE}");
        let seen: Arc<Mutex<BTreeMap<String, Sighting>>> = Arc::default();
        let seen2 = seen.clone();
        // Ends when the daemon shuts down and drops the channel.
        std::thread::Builder::new()
            .name("tethra-mesh-mdns".into())
            .spawn(move || {
                for event in rx.iter() {
                    let mut seen = seen2.lock().unwrap_or_else(PoisonError::into_inner);
                    match event {
                        mdns_sd::ServiceEvent::ServiceResolved(info) => {
                            if info.fullname == own_fullname || seen.len() >= 256 {
                                continue;
                            }
                            let txt = info
                                .txt_properties
                                .iter()
                                .take(8)
                                .map(|p| (p.key().to_owned(), p.val_str().to_owned()))
                                .collect();
                            let addrs = info
                                .addresses
                                .iter()
                                .take(8)
                                .map(|ip| SocketAddr::new(ip.to_ip_addr(), info.port))
                                .collect();
                            seen.insert(info.fullname.clone(), Sighting { addrs, txt });
                        }
                        mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                            seen.remove(&fullname);
                        }
                        _ => {}
                    }
                }
            })
            .map_err(|_| NetError::Node("mDNS discovery could not start"))?;
        Ok(Self {
            daemon,
            host: format!("{}.local.", random_name("h")),
            instance,
            registered: Mutex::new(None),
            seen,
        })
    }
}

impl Discovery for MdnsDiscovery {
    fn announce(&self, port: u16, ips: &[IpAddr], txt: &BTreeMap<String, String>) -> NetResult<()> {
        let props: HashMap<String, String> = txt.clone().into_iter().collect();
        let ips: Vec<IpAddr> = ips.to_vec();
        let mut info =
            mdns_sd::ServiceInfo::new(SERVICE, &self.instance, &self.host, &ips[..], port, props)
                .map_err(|_| NetError::Node("the mDNS announcement is invalid"))?;
        if ips.is_empty() {
            info = info.enable_addr_auto();
        }
        let mut reg = self
            .registered
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(old) = reg.take() {
            let _ = self.daemon.unregister(&old);
        }
        let fullname = info.get_fullname().to_owned();
        self.daemon
            .register(info)
            .map_err(|_| NetError::Node("the mDNS announcement could not be registered"))?;
        *reg = Some(fullname);
        Ok(())
    }

    fn browse(&self) -> Vec<Sighting> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}
