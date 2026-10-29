//! The addresses a node dials and what it learned from them (Increment 05).
//! Local-only: `mesh_peers` and the `node/…` rows of `mesh_meta` never
//! replicate (PROTOCOL.md §10), and a restore or `mesh leave` deletes them.
//!
//! - **Sources.** `manual` (`tethra mesh peer add`), `gossip` (the
//!   `device.info` listen addresses other active devices publish) and `mdns`
//!   (opt-in discovery). A manual row is never downgraded; learned rows are
//!   replaced wholesale by [`sync_learned`] so an address a device stopped
//!   publishing stops being dialled.
//! - **Attempts.** Every dial records `last_attempt_at`, and either
//!   `last_success_at` and the device the handshake revealed, or a failure
//!   count, `unreachable_since` and a static reason. When a *different*
//!   device answers at an address (expected after a device pairs again), the
//!   change is kept in `mesh_meta` and surfaced by `status`.
//! - **Lag.** After each exchange the node stores the peer's `Hello` VV and
//!   this device's VV at that moment (`node/peer/<device>`), from which
//!   [`lag`] derives how far apart the two were, and how far the peer has
//!   fallen behind this device since.
//!
//! Nothing here touches the network; the dialling is `api-tracker-mesh`.
//! Timestamps come from the node's injected clock (milliseconds) and are
//! stored as RFC 3339 like the rest of `mesh_peers`.

use super::dot::DeviceId;
use super::error::MeshError;
use super::kinds::MAX_ADDR_BYTES;
use super::vv::VersionVector;
use crate::error::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Where a peer address came from. Ordered by precedence: a manual address
/// stays manual whatever else also lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerSource {
    Mdns,
    Gossip,
    Manual,
}

impl PeerSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerSource::Manual => "manual",
            PeerSource::Gossip => "gossip",
            PeerSource::Mdns => "mdns",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "manual" => Some(PeerSource::Manual),
            "gossip" => Some(PeerSource::Gossip),
            "mdns" => Some(PeerSource::Mdns),
            _ => None,
        }
    }
}

/// One row of `mesh_peers`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PeerRow {
    pub addr: String,
    /// The device that answered at this address, once a handshake succeeded.
    pub device_id: Option<DeviceId>,
    pub source: PeerSource,
    pub last_attempt_at: Option<String>,
    pub last_success_at: Option<String>,
    /// Consecutive failed attempts (0 after a success).
    pub failures: u32,
    pub unreachable_since: Option<String>,
    /// A static description of the last failure; never peer-supplied text.
    pub last_error: Option<String>,
}

/// Normalize a `HOST:PORT` peer address: an IPv4 or bracketed IPv6 address,
/// or a host name (a LAN or VPN name such as `laptop.tailnet.ts.net`), and
/// a port from 1 to 65535. The result is what gets stored and dialled.
pub fn normalize_addr(raw: &str) -> std::result::Result<String, MeshError> {
    let s = raw.trim();
    if s.is_empty()
        || s.len() > MAX_ADDR_BYTES
        || s.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(MeshError::InvalidPeerAddress);
    }
    if let Ok(sock) = s.parse::<std::net::SocketAddr>() {
        if sock.port() == 0 || sock.ip().is_unspecified() || sock.ip().is_multicast() {
            return Err(MeshError::InvalidPeerAddress);
        }
        return Ok(sock.to_string());
    }
    let (host, port) = s.rsplit_once(':').ok_or(MeshError::InvalidPeerAddress)?;
    let port: u16 = port.parse().map_err(|_| MeshError::InvalidPeerAddress)?;
    let host_ok = !host.is_empty()
        && !host.starts_with('-')
        && !host.starts_with('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
    if port == 0 || !host_ok {
        return Err(MeshError::InvalidPeerAddress);
    }
    Ok(format!("{}:{port}", host.to_ascii_lowercase()))
}

fn ms_to_rfc3339(ms: u64) -> String {
    let nanos = i128::from(ms) * 1_000_000;
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    crate::clock::to_rfc3339(t)
}

/// Parse a `mesh_peers` timestamp back to milliseconds (0 if unreadable).
pub fn rfc3339_to_ms(s: &str) -> u64 {
    crate::clock::parse_rfc3339(s)
        .ok()
        .and_then(|t| u64::try_from(t.unix_timestamp_nanos() / 1_000_000).ok())
        .unwrap_or(0)
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(PeerRow, String)> {
    let device: Option<String> = r.get(1)?;
    let source: String = r.get(2)?;
    let failures: i64 = r.get(6)?;
    Ok((
        PeerRow {
            addr: r.get(0)?,
            device_id: device.and_then(|d| DeviceId::parse(&d).ok()),
            source: PeerSource::parse(&source).unwrap_or(PeerSource::Gossip),
            last_attempt_at: r.get(3)?,
            last_success_at: r.get(4)?,
            failures: u32::try_from(failures).unwrap_or(u32::MAX),
            unreachable_since: r.get(5)?,
            last_error: r.get(7)?,
        },
        source,
    ))
}

const COLUMNS: &str = "addr, device_id, source, last_attempt_at, last_success_at, \
                       unreachable_since, failures, last_error";

/// Every peer address, manual ones first, then by address.
pub fn list(conn: &Connection) -> Result<Vec<PeerRow>> {
    let mut st = conn.prepare(&format!("SELECT {COLUMNS} FROM mesh_peers"))?;
    let mut out: Vec<PeerRow> = st
        .query_map([], row)?
        .map(|r| r.map(|(p, _)| p))
        .collect::<rusqlite::Result<_>>()?;
    out.sort_by(|a, b| b.source.cmp(&a.source).then_with(|| a.addr.cmp(&b.addr)));
    Ok(out)
}

pub fn get(conn: &Connection, addr: &str) -> Result<Option<PeerRow>> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM mesh_peers WHERE addr = ?1"),
            [addr],
            row,
        )
        .optional()?
        .map(|(p, _)| p))
}

/// Add (or promote to) a manual peer. Returns the normalized address and
/// whether anything changed.
pub fn add_manual(conn: &Connection, raw: &str) -> Result<(String, bool)> {
    let addr = normalize_addr(raw)?;
    let changed = conn.execute(
        "INSERT INTO mesh_peers (addr, source) VALUES (?1, 'manual')
         ON CONFLICT(addr) DO UPDATE SET source = 'manual' WHERE source <> 'manual'",
        [&addr],
    )?;
    Ok((addr, changed > 0))
}

/// Forget an address, whatever its source. A gossip or mDNS address comes
/// back at the next round if a device still publishes it. Returns the
/// source of the removed row.
pub fn remove(conn: &Connection, raw: &str) -> Result<Option<PeerSource>> {
    let addr = normalize_addr(raw)?;
    let source = get(conn, &addr)?.map(|p| p.source);
    conn.execute("DELETE FROM mesh_peers WHERE addr = ?1", [&addr])?;
    conn.execute(
        "DELETE FROM mesh_meta WHERE key = ?1",
        [format!("node/addr_changed/{addr}")],
    )?;
    Ok(source)
}

/// Make the learned addresses of `source` exactly `addrs`: insert new ones,
/// promote mDNS rows that gossip also lists, and delete rows of this source
/// no longer listed. Manual rows are never touched.
pub fn sync_learned(conn: &Connection, source: PeerSource, addrs: &BTreeSet<String>) -> Result<()> {
    debug_assert!(source != PeerSource::Manual);
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let existing: BTreeMap<String, PeerSource> = {
        let mut st = tx.prepare("SELECT addr, source FROM mesh_peers")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        rows.filter_map(|r| r.ok())
            .filter_map(|(a, s)| PeerSource::parse(&s).map(|s| (a, s)))
            .collect()
    };
    for addr in addrs {
        let Ok(addr) = normalize_addr(addr) else {
            continue;
        };
        match existing.get(&addr) {
            None => {
                tx.execute(
                    "INSERT INTO mesh_peers (addr, source) VALUES (?1, ?2)",
                    params![addr, source.as_str()],
                )?;
            }
            Some(s) if *s < source => {
                tx.execute(
                    "UPDATE mesh_peers SET source = ?2 WHERE addr = ?1",
                    params![addr, source.as_str()],
                )?;
            }
            Some(_) => {}
        }
    }
    let keep: BTreeSet<String> = addrs
        .iter()
        .filter_map(|a| normalize_addr(a).ok())
        .collect();
    for (addr, s) in &existing {
        if *s == source && !keep.contains(addr) {
            tx.execute("DELETE FROM mesh_peers WHERE addr = ?1", [addr])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// How one dial ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The handshake authenticated this device (the exchange may still have
    /// ended early; that is recorded in the exchange log).
    Reached(DeviceId),
    /// Static text only.
    Failed(&'static str),
}

/// A different device answered at an address that used to reach another
/// one, typically after that device paired again under a new identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceChange {
    pub addr: String,
    pub from: DeviceId,
    pub to: DeviceId,
    pub at: String,
}

/// Record one dial of `addr`. Only addresses already in the table are
/// recorded: an ad-hoc `replicate --peer` does not add a peer.
pub fn record_attempt(
    conn: &Connection,
    addr: &str,
    at_ms: u64,
    outcome: AttemptOutcome,
) -> Result<Option<DeviceChange>> {
    let at = ms_to_rfc3339(at_ms);
    let Some(previous) = get(conn, addr)? else {
        return Ok(None);
    };
    let previous = Some(previous);
    match outcome {
        AttemptOutcome::Reached(device) => {
            conn.execute(
                "UPDATE mesh_peers SET device_id = ?2, last_attempt_at = ?3,
                     last_success_at = ?3, failures = 0, unreachable_since = NULL,
                     last_error = NULL
                 WHERE addr = ?1",
                params![addr, device.to_hex(), at],
            )?;
            let change = previous
                .and_then(|p| p.device_id)
                .filter(|from| *from != device)
                .map(|from| DeviceChange {
                    addr: addr.to_owned(),
                    from,
                    to: device,
                    at: at.clone(),
                });
            if let Some(c) = &change {
                conn.execute(
                    "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES (?1, ?2)",
                    params![
                        format!("node/addr_changed/{addr}"),
                        serde_json::to_string(c).unwrap_or_default()
                    ],
                )?;
            }
            Ok(change)
        }
        AttemptOutcome::Failed(why) => {
            conn.execute(
                "UPDATE mesh_peers SET last_attempt_at = ?2, failures = failures + 1,
                     unreachable_since = COALESCE(unreachable_since, ?2), last_error = ?3
                 WHERE addr = ?1",
                params![addr, at, why],
            )?;
            Ok(None)
        }
    }
}

/// Addresses at which a different device answered than before.
pub fn device_changes(conn: &Connection) -> Result<Vec<DeviceChange>> {
    let mut st = conn
        .prepare("SELECT value FROM mesh_meta WHERE key LIKE 'node/addr_changed/%' ORDER BY key")?;
    let rows = st.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows
        .filter_map(|r| r.ok())
        .filter_map(|v| serde_json::from_str(&v).ok())
        .collect())
}

/// The un-jittered backoff after `failures` consecutive failures: 5 s,
/// doubling, at most 15 minutes (DESIGN §D13). The node spreads each delay
/// by ±20% so devices that failed together do not retry together.
pub fn backoff_ms(failures: u32) -> u64 {
    const BASE: u64 = 5_000;
    const MAX: u64 = 15 * 60 * 1_000;
    if failures == 0 {
        return 0;
    }
    let shift = (failures - 1).min(20);
    (BASE << shift).min(MAX)
}

// ------------------------------------------------------------------ lag

/// What the peer's last `Hello` said, beside this device's state then.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloRecord {
    pub at_ms: u64,
    /// Whether the exchange that started with this `Hello` completed (both
    /// sides committed what the other sent).
    pub completed: bool,
    pub peer_vv: BTreeMap<DeviceId, u64>,
    pub our_vv: BTreeMap<DeviceId, u64>,
    /// Origins whose VVs were equal but whose held items differed (their
    /// digests disagreed), so the exchange repaired them (PROTOCOL.md §8.5).
    pub digest_mismatches: Vec<DeviceId>,
}

fn hello_key(device: &DeviceId) -> String {
    format!("node/peer/{}", device.to_hex())
}

pub fn record_hello(conn: &Connection, device: &DeviceId, rec: &HelloRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES (?1, ?2)",
        params![hello_key(device), serde_json::to_string(rec)?],
    )?;
    Ok(())
}

pub fn hello_records(conn: &Connection) -> Result<BTreeMap<DeviceId, HelloRecord>> {
    let mut st = conn.prepare("SELECT key, value FROM mesh_meta WHERE key LIKE 'node/peer/%'")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = BTreeMap::new();
    for (k, v) in rows.filter_map(|r| r.ok()) {
        let Some(d) = k
            .strip_prefix("node/peer/")
            .and_then(|d| DeviceId::parse(d).ok())
        else {
            continue;
        };
        if let Ok(rec) = serde_json::from_str::<HelloRecord>(&v) {
            out.insert(d, rec);
        }
    }
    Ok(out)
}

/// How far apart this device and a peer are, per origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PeerLag {
    pub at: String,
    pub completed: bool,
    /// Per origin, `peer seq − this device's seq` at the last `Hello`:
    /// positive when the peer was ahead, negative when it was behind. Only
    /// origins that differed are listed.
    pub at_hello: BTreeMap<DeviceId, i64>,
    /// Items the peer lacked at that `Hello` (sum of the negative entries).
    pub peer_behind: u64,
    /// Items this device lacked at that `Hello` (sum of the positive ones).
    pub peer_ahead: u64,
    /// Items this device holds now that the peer, as far as this device
    /// knows, still lacks: its `Hello` VV, joined with what this device sent
    /// it if the exchange completed, compared with this device's VV now.
    pub peer_behind_now: u64,
    pub digest_mismatches: usize,
}

pub fn lag(rec: &HelloRecord, ours_now: &VersionVector) -> PeerLag {
    let origins: BTreeSet<&DeviceId> = rec.peer_vv.keys().chain(rec.our_vv.keys()).collect();
    let mut at_hello = BTreeMap::new();
    let (mut behind, mut ahead) = (0u64, 0u64);
    for o in &origins {
        let p = rec.peer_vv.get(o).copied().unwrap_or(0);
        let q = rec.our_vv.get(o).copied().unwrap_or(0);
        if p != q {
            let diff = i128::from(p) - i128::from(q);
            at_hello.insert(
                **o,
                i64::try_from(diff).unwrap_or(if diff > 0 { i64::MAX } else { i64::MIN }),
            );
        }
        behind = behind.saturating_add(q.saturating_sub(p));
        ahead = ahead.saturating_add(p.saturating_sub(q));
    }
    let mut now_behind = 0u64;
    for (o, s) in ours_now.iter() {
        let known = rec.peer_vv.get(o).copied().unwrap_or(0);
        let known = if rec.completed {
            known.max(rec.our_vv.get(o).copied().unwrap_or(0))
        } else {
            known
        };
        now_behind = now_behind.saturating_add(s.saturating_sub(known));
    }
    PeerLag {
        at: ms_to_rfc3339(rec.at_ms),
        completed: rec.completed,
        at_hello,
        peer_behind: behind,
        peer_ahead: ahead,
        peer_behind_now: now_behind,
        digest_mismatches: rec.digest_mismatches.len(),
    }
}

/// The last repair round a node ran (`doctor --repair`, or the daily one):
/// when, and whether it changed stored state (`repairs_changed` moved).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRecord {
    pub at_ms: u64,
    pub exchanges: u64,
    pub changed: u64,
}

pub fn record_repair(conn: &Connection, rec: &RepairRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES ('node/last_repair', ?1)",
        [serde_json::to_string(rec)?],
    )?;
    Ok(())
}

pub fn last_repair(conn: &Connection) -> Result<Option<RepairRecord>> {
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM mesh_meta WHERE key = 'node/last_repair'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(v.and_then(|v| serde_json::from_str(&v).ok()))
}

/// When a node last ran repair on this device (ms), for the 24-hour timer.
pub fn last_repair_ms(conn: &Connection) -> u64 {
    last_repair(conn).ok().flatten().map_or(0, |r| r.at_ms)
}

pub fn ms_rfc3339(ms: u64) -> String {
    ms_to_rfc3339(ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn conn() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let mut c = db::open(&dir.path().join("vault.db")).unwrap();
        db::migrate(&mut c).unwrap();
        (dir, c)
    }

    fn dev(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    #[test]
    fn addresses_are_validated_and_normalized() {
        for ok in [
            "127.0.0.1:7420",
            " 100.64.0.2:7420 ",
            "[::1]:7420",
            "Laptop.Tail1.ts.net:7420",
            "nas_box:1",
        ] {
            normalize_addr(ok).unwrap();
        }
        assert_eq!(
            normalize_addr("Laptop.Tail1.ts.net:7420").unwrap(),
            "laptop.tail1.ts.net:7420"
        );
        for bad in [
            "",
            "laptop",
            "laptop:",
            "laptop:0",
            "laptop:70000",
            "0.0.0.0:7420",
            "[::]:7420",
            "224.0.0.251:5353",
            "a b:1",
            "-x:1",
            "x/y:1",
            "http://laptop:1",
        ] {
            assert!(normalize_addr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn manual_peers_survive_learned_syncs_and_learned_ones_follow_the_source() {
        let (_d, c) = conn();
        add_manual(&c, "10.0.0.1:1").unwrap();
        let g: BTreeSet<String> = ["10.0.0.1:1", "10.0.0.2:1"].map(String::from).into();
        sync_learned(&c, PeerSource::Gossip, &g).unwrap();
        let m: BTreeSet<String> = ["10.0.0.2:1", "10.0.0.3:1"].map(String::from).into();
        sync_learned(&c, PeerSource::Mdns, &m).unwrap();
        let rows = list(&c).unwrap();
        let src: BTreeMap<_, _> = rows.iter().map(|r| (r.addr.as_str(), r.source)).collect();
        assert_eq!(src["10.0.0.1:1"], PeerSource::Manual);
        assert_eq!(src["10.0.0.2:1"], PeerSource::Gossip);
        assert_eq!(src["10.0.0.3:1"], PeerSource::Mdns);
        sync_learned(&c, PeerSource::Gossip, &BTreeSet::new()).unwrap();
        let addrs: Vec<_> = list(&c).unwrap().into_iter().map(|r| r.addr).collect();
        assert_eq!(addrs, ["10.0.0.1:1", "10.0.0.3:1"]);
        assert_eq!(remove(&c, "10.0.0.1:1").unwrap(), Some(PeerSource::Manual));
        assert_eq!(remove(&c, "10.0.0.1:1").unwrap(), None);
    }

    #[test]
    fn attempts_count_failures_and_a_success_resets_them_and_flags_a_new_device() {
        let (_d, c) = conn();
        let a = "10.0.0.9:7420";
        add_manual(&c, a).unwrap();
        record_attempt(&c, a, 1_000, AttemptOutcome::Failed("connection failed")).unwrap();
        record_attempt(&c, a, 2_000, AttemptOutcome::Failed("connection failed")).unwrap();
        let p = get(&c, a).unwrap().unwrap();
        assert_eq!(p.failures, 2);
        assert_eq!(p.unreachable_since.as_deref(), Some(&*ms_to_rfc3339(1_000)));
        assert_eq!(p.last_error.as_deref(), Some("connection failed"));
        assert!(
            record_attempt(&c, a, 3_000, AttemptOutcome::Reached(dev(1)))
                .unwrap()
                .is_none()
        );
        let p = get(&c, a).unwrap().unwrap();
        assert_eq!((p.failures, p.device_id), (0, Some(dev(1))));
        assert!(p.unreachable_since.is_none() && p.last_error.is_none());
        let change = record_attempt(&c, a, 4_000, AttemptOutcome::Reached(dev(2)))
            .unwrap()
            .unwrap();
        assert_eq!((change.from, change.to), (dev(1), dev(2)));
        assert_eq!(device_changes(&c).unwrap(), vec![change]);
    }

    #[test]
    fn backoff_doubles_from_five_seconds_to_fifteen_minutes() {
        assert_eq!(backoff_ms(0), 0);
        assert_eq!(backoff_ms(1), 5_000);
        assert_eq!(backoff_ms(2), 10_000);
        assert_eq!(backoff_ms(5), 80_000);
        assert_eq!(backoff_ms(8), 640_000);
        assert_eq!(backoff_ms(9), 900_000);
        assert_eq!(backoff_ms(u32::MAX), 900_000);
    }

    #[test]
    fn lag_compares_vvs_at_hello_and_now() {
        let mut ours_now = VersionVector::new();
        ours_now.advance_to(dev(1), 12);
        ours_now.advance_to(dev(2), 3);
        let rec = HelloRecord {
            at_ms: 5,
            completed: true,
            peer_vv: [(dev(1), 7), (dev(3), 4)].into(),
            our_vv: [(dev(1), 10), (dev(2), 3)].into(),
            digest_mismatches: vec![dev(2)],
        };
        let l = lag(&rec, &ours_now);
        assert_eq!(l.at_hello[&dev(1)], -3);
        assert_eq!(l.at_hello[&dev(2)], -3);
        assert_eq!(l.at_hello[&dev(3)], 4);
        assert_eq!((l.peer_behind, l.peer_ahead), (6, 4));
        // Completed: the peer got up to 10 of dev(1) and 3 of dev(2).
        assert_eq!(l.peer_behind_now, 2);
        let l = lag(
            &HelloRecord {
                completed: false,
                ..rec
            },
            &ours_now,
        );
        assert_eq!(l.peer_behind_now, 5 + 3);
    }

    #[test]
    fn hello_and_repair_records_round_trip_and_never_disturb_the_store_counters() {
        let (_d, c) = conn();
        let rec = HelloRecord {
            at_ms: 9,
            completed: false,
            peer_vv: [(dev(1), 1)].into(),
            our_vv: BTreeMap::new(),
            digest_mismatches: vec![],
        };
        record_hello(&c, &dev(4), &rec).unwrap();
        assert_eq!(hello_records(&c).unwrap()[&dev(4)], rec);
        assert!(last_repair(&c).unwrap().is_none());
        let r = RepairRecord {
            at_ms: 77,
            exchanges: 2,
            changed: 1,
        };
        record_repair(&c, &r).unwrap();
        assert_eq!(last_repair(&c).unwrap(), Some(r));
        assert_eq!(last_repair_ms(&c), 77);
    }
}
