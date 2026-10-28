//! Opt-in discovery (Increment 05, DESIGN §D13): what an announcement says
//! (only `v` and a daily mesh tag), that only the access key recognises it,
//! that names are random per boot, that a node finds a peer through it, and
//! that no test ever multicasts.

mod common;

use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::kinds::Day;
use api_tracker_core::mesh::peers::PeerSource;
use api_tracker_mesh::discover::{self, Discovery, FakeDiscovery, Sighting};
use api_tracker_mesh::runtime::Never;
use common::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const KEY: [u8; 32] = [0x11; 32];
const OTHER: [u8; 32] = [0x22; 32];
const NOON: u64 = 1_800_000_000_000; // 2027-01-15, mid-day UTC
const DAY: u64 = 86_400_000;

fn sighting(txt: BTreeMap<String, String>) -> Sighting {
    Sighting {
        addrs: vec!["127.0.0.1:9".parse().unwrap()],
        txt,
    }
}

#[test]
fn the_txt_record_holds_only_the_version_and_a_mesh_tag() {
    let t = discover::txt(&KEY, NOON);
    assert_eq!(t.keys().collect::<Vec<_>>(), ["m", "v"]);
    assert_eq!(t["v"], "1");
    let m = &t["m"];
    assert_eq!(m.len(), 16);
    assert!(m
        .bytes()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(m, &discover::tag(&KEY, Day::from_unix_ms(NOON)));
}

#[test]
fn the_tag_rotates_every_utc_day_and_only_the_access_key_recognises_it() {
    let today = discover::tag(&KEY, Day::from_unix_ms(NOON));
    let tomorrow = discover::tag(&KEY, Day::from_unix_ms(NOON + DAY));
    assert_ne!(today, tomorrow);
    // The same all day long.
    assert_eq!(
        today,
        discover::tag(&KEY, Day::from_unix_ms(NOON + DAY / 3))
    );
    // Another key (another mesh, or an outsider guessing) gets another tag.
    assert_ne!(today, discover::tag(&OTHER, Day::from_unix_ms(NOON)));
    let s = sighting(discover::txt(&KEY, NOON));
    assert!(discover::recognises(&s, &[&KEY], NOON));
    assert!(!discover::recognises(&s, &[&OTHER], NOON));
    // A rotated key's members still recognise the previous one.
    assert!(discover::recognises(&s, &[&OTHER, &KEY], NOON));
    // Clocks either side of midnight still match; a stale tag does not.
    assert!(discover::recognises(&s, &[&KEY], NOON + DAY));
    assert!(discover::recognises(&s, &[&KEY], NOON - DAY));
    assert!(!discover::recognises(&s, &[&KEY], NOON + 2 * DAY));
    // Wrong version, or no tag at all.
    let mut v2 = discover::txt(&KEY, NOON);
    v2.insert("v".into(), "2".into());
    assert!(!discover::recognises(&sighting(v2), &[&KEY], NOON));
    let mut no_m = discover::txt(&KEY, NOON);
    no_m.remove("m");
    assert!(!discover::recognises(&sighting(no_m), &[&KEY], NOON));
}

#[test]
fn instance_names_are_random_per_boot_and_name_nothing() {
    let a = FakeDiscovery::network();
    let b = a.join();
    assert_ne!(a.instance_name(), b.instance_name());
    let names: std::collections::BTreeSet<String> =
        (0..64).map(|_| discover::random_name("tethra-")).collect();
    assert_eq!(names.len(), 64);
    let host = std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_lowercase())
        .unwrap_or_default();
    for n in &names {
        assert!(
            n.starts_with("tethra-") && n.len() == "tethra-".len() + 16,
            "{n}"
        );
        if !host.is_empty() {
            assert!(!n.contains(&host));
        }
    }
}

#[test]
fn a_node_finds_a_peer_through_discovery_alone_and_ignores_strangers() {
    let net = FakeDiscovery::network();
    let a = genesis("dev-a");
    let mut ca = node_config(200);
    ca.discovery = Some(Arc::new(net.join()));
    // A publishes an address nobody can use, so gossip cannot be what lets
    // B find it.
    ca.advertise = vec!["127.0.0.1:1".into()];
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let na = run_node(&a, ca, clock.clone(), Box::new(Never));
    let a_port = na.listen_addrs()[0].port();
    let b = vault();
    join_via(&a, &na.listen_addrs()[0].to_string(), &b, "dev-b");
    // Joining recorded the invite's address as a peer; forget it, so only
    // discovery can lead B to A.
    let a_addr = na.listen_addrs()[0].to_string();
    assert!(b.vault.mesh_peer_remove(&a_addr).unwrap().is_some());
    // A stranger on the same network, announcing with another key.
    net.inject(
        "stranger",
        Sighting {
            addrs: vec!["127.0.0.1:2".parse().unwrap()],
            txt: discover::txt(&OTHER, clock.now_ms()),
        },
    );
    let mut cb = node_config(200);
    cb.discovery = Some(Arc::new(net.join()));
    let nb = run_node(&b, cb, clock, Box::new(Never));
    let a_mdns = format!("127.0.0.1:{a_port}");
    wait_for(
        20,
        || {
            b.vault.mesh_peers().unwrap().iter().any(|r| {
                r.addr == a_mdns && r.source == PeerSource::Mdns && r.last_success_at.is_some()
            })
        },
        "B to reach A at the address mDNS announced",
    );
    let peers = b.vault.mesh_peers().unwrap();
    assert!(
        peers.iter().all(|r| r.addr != "127.0.0.1:2"),
        "a stranger's announcement became a peer: {peers:?}"
    );
    // What A announced: only v and m, A's port, nothing that names it.
    let mut seen = Vec::new();
    for s in net.join().browse() {
        if s.addrs.iter().any(|x| x.port() == a_port) {
            seen.push(s);
        }
    }
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].txt.keys().collect::<Vec<_>>(), ["m", "v"]);
    for n in [na, nb] {
        n.stop();
        assert!(n.wait().keys_dropped);
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// CI must never multicast: no test, anywhere in the workspace, constructs
/// the real mDNS discovery. (The needle is split so this file passes.)
#[test]
fn no_test_constructs_the_real_mdns_discovery() {
    let needle = format!("{}::{}", "MdnsDiscovery", "new");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for dir in ["crates", "apps"] {
        let d = root.join(dir);
        if d.exists() {
            rust_files(&d, &mut files);
        }
    }
    let mut checked = 0;
    for f in files {
        let s = f.to_string_lossy().replace('\\', "/");
        if s.contains("/target/") || s.contains("/node_modules/") {
            continue;
        }
        let src = std::fs::read_to_string(&f).unwrap();
        let in_tests = s.contains("/tests/");
        let test_mod = src.find("#[cfg(test)]").map(|i| &src[i..]);
        if in_tests {
            checked += 1;
            assert!(
                !src.contains(&needle),
                "{} constructs MdnsDiscovery",
                f.display()
            );
        } else if let Some(tail) = test_mod {
            checked += 1;
            assert!(
                !tail.contains(&needle),
                "{}: a unit test constructs MdnsDiscovery",
                f.display()
            );
        }
    }
    assert!(checked > 20, "only {checked} test sources scanned");
}
