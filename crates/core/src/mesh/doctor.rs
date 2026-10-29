//! The store-side checks of `tethra mesh doctor` (Increment 05). The
//! network-side checks (the node, its listener, a repair round) are in
//! `api-tracker-mesh::doctor`, which runs these first.
//!
//! Every check reports a [`Finding`] with a plain-language fix. Nothing here
//! prints or returns key material: the keys are unwrapped only to compare
//! each with its public key (as the node does when it starts), and the
//! sealing key is never unwrapped at all (MESH-SI-7); only its presence is
//! checked.
//!
//! `--rebuild` ([`DoctorOptions::rebuild`]): the views are derived from
//! `mesh_items` in memory (ADR 0031 R17), so what can be rebuilt is the item
//! store itself. Its `origin`, `seq`, `hash`, `kind` and `item_key` columns
//! are a projection of `bytes`, and are rewritten from them. A row whose bytes
//! no longer parse, or no longer carry a valid signature by their origin, is
//! removed: it cannot be used or relayed. The version vector and dot log are
//! untouched, so the next exchange with a peer that holds the item finds the
//! origin's digest different at equal VVs and repairs it (PROTOCOL.md §8.5).

use super::dot::DeviceId;
use super::identity;
use super::item::SignedItem;
use super::marker::MarkerStatus;
use super::peers;
use super::sqlite_store::SqliteStore;
use super::store::MeshStore;
use crate::db;
use crate::error::Result;
use crate::secret::SecretBytes;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Problem,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Ok => "ok",
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Problem => "problem",
        }
    }
}

/// One check's result. `summary` and `fix` are built from static text,
/// counts and device ids only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub check: &'static str,
    pub severity: Severity,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Finding {
    pub fn ok(check: &'static str, summary: impl Into<String>) -> Self {
        Self {
            check,
            severity: Severity::Ok,
            summary: summary.into(),
            fix: None,
        }
    }

    pub fn new(
        check: &'static str,
        severity: Severity,
        summary: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            check,
            severity,
            summary: summary.into(),
            fix: Some(fix.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DoctorOptions {
    /// Rewrite the item store's derived columns and drop unusable rows.
    pub rebuild: bool,
}

/// What `--rebuild` changed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RebuildReport {
    pub rows_rewritten: u64,
    pub rows_removed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoreDoctorReport {
    pub initialized: bool,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebuild: Option<RebuildReport>,
}

fn short(d: &DeviceId) -> String {
    d.to_hex()[..8].to_owned()
}

/// One raw `mesh_items` row and what its bytes say.
struct ScannedRow {
    origin: String,
    seq: i64,
    hash: Vec<u8>,
    kind: String,
    item_key: String,
    received_at: i64,
    bytes: Vec<u8>,
    /// `None` when the bytes do not parse.
    item: Option<(SignedItem, super::codec::ItemBody)>,
}

impl ScannedRow {
    fn columns_match(&self) -> bool {
        self.item.as_ref().is_some_and(|(item, body)| {
            self.origin == body.origin.to_hex()
                && u64::try_from(self.seq).ok() == Some(body.seq)
                && self.hash == item.hash().0
                && self.kind == body.kind
                && self.item_key == body.key
        })
    }
}

fn scan_items(conn: &Connection) -> Result<Vec<ScannedRow>> {
    let mut st = conn.prepare(
        "SELECT origin, seq, hash, kind, item_key, received_at, bytes FROM mesh_items
         ORDER BY origin, seq, hash",
    )?;
    let rows = st.query_map([], |r| {
        Ok(ScannedRow {
            origin: r.get(0)?,
            seq: r.get(1)?,
            hash: r.get(2)?,
            kind: r.get(3)?,
            item_key: r.get(4)?,
            received_at: r.get(5)?,
            bytes: r.get(6)?,
            item: None,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        let mut row = row?;
        row.item = SignedItem::from_wire(&row.bytes)
            .ok()
            .and_then(|i| i.decode_unverified().ok().map(|b| (i, b)));
        out.push(row);
    }
    Ok(out)
}

/// Rows whose signature does not verify with the key the roster holds for
/// their origin (the roster built from the readable rows). `None` entries
/// are rows whose origin the roster does not know.
fn unsigned_rows(rows: &[ScannedRow], store: &SqliteStore) -> (Vec<usize>, usize) {
    let roster = &store.state().roster;
    let mesh = store.genesis().mesh_id;
    let mut bad = Vec::new();
    let mut unknown = 0;
    for (i, r) in rows.iter().enumerate() {
        let Some((item, body)) = &r.item else {
            continue;
        };
        let Some(key) = roster
            .keys(&body.origin)
            .and_then(|k| k.sign_pub.to_verifying_key().ok())
        else {
            unknown += 1;
            continue;
        };
        if item.verify_with(&key, &mesh).is_err() {
            bad.push(i);
        }
    }
    (bad, unknown)
}

/// `(kind, item_key, origin)` → the greatest `(seq, hash)` seen and its row.
type Latest = BTreeMap<(String, String, String), (u64, [u8; 32], usize)>;

/// Rewrite every readable row from its bytes, dropping unreadable rows,
/// rows in `drop`, and (if corruption made two rows claim one
/// `(kind, key, origin)`) all but the greatest `(seq, hash)`. One
/// transaction; the write generation moves so a running node reloads.
fn rebuild_items(conn: &Connection, rows: &[ScannedRow], drop: &[usize]) -> Result<RebuildReport> {
    let mut keep: Latest = BTreeMap::new();
    let mut report = RebuildReport::default();
    for (i, r) in rows.iter().enumerate() {
        let Some((item, body)) = &r.item else {
            report.rows_removed += 1;
            continue;
        };
        if drop.contains(&i) {
            report.rows_removed += 1;
            continue;
        }
        let k = (body.kind.clone(), body.key.clone(), body.origin.to_hex());
        let cand = (body.seq, item.hash().0, i);
        match keep.get(&k) {
            Some(cur) if (cur.0, cur.1) >= (cand.0, cand.1) => report.rows_removed += 1,
            Some(_) => {
                report.rows_removed += 1;
                keep.insert(k, cand);
            }
            None => {
                keep.insert(k, cand);
            }
        }
    }
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    tx.execute("DELETE FROM mesh_items", [])?;
    for (_, _, i) in keep.values() {
        let r = &rows[*i];
        let (item, body) = r.item.as_ref().expect("kept rows parse");
        if !r.columns_match() {
            report.rows_rewritten += 1;
        }
        tx.execute(
            "INSERT INTO mesh_items (origin, seq, hash, kind, item_key, bytes, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                body.origin.to_hex(),
                i64::try_from(body.seq).unwrap_or(i64::MAX),
                item.hash().0.as_slice(),
                body.kind,
                body.key,
                r.bytes,
                r.received_at,
            ],
        )?;
    }
    tx.execute(
        "INSERT INTO mesh_meta (key, value) VALUES ('write_gen', 1)
         ON CONFLICT(key) DO UPDATE SET value = value + 1",
        [],
    )?;
    tx.commit()?;
    Ok(report)
}

/// Run the store-side checks (and `--rebuild` if asked). `conn` is the
/// vault's connection; the store is opened on its own.
pub fn run(
    conn: &Connection,
    db_path: &Path,
    data_dir: &Path,
    vault_key: &SecretBytes,
    vault_id: &str,
    opts: DoctorOptions,
) -> Result<StoreDoctorReport> {
    let mut findings = Vec::new();
    // Schema: the node opens the database only at this binary's version.
    match db::open_at_current_version(db_path) {
        Ok(_) => findings.push(Finding::ok(
            "schema",
            format!("database schema v{}", db::current_schema_version()),
        )),
        Err(_) => findings.push(Finding::new(
            "schema",
            Severity::Problem,
            "the database schema does not match this version of Tethra",
            "if another Tethra version upgraded this vault, run that version (or a newer one); \
             otherwise run any `tethra` command once so this one migrates it",
        )),
    }
    let Some(me) = identity::read_self(conn)? else {
        findings.push(Finding::ok(
            "identity",
            "this device is not part of a mesh; nothing else to check",
        ));
        return Ok(StoreDoctorReport {
            initialized: false,
            findings,
            rebuild: None,
        });
    };
    let device = me.info.device_id;
    // Keys: unwrap the node's keys and compare each with its public key.
    match identity::load_keys(conn, vault_key, vault_id) {
        Ok(keys) => {
            drop(keys);
            findings.push(Finding::ok(
                "keys",
                "the signing, Noise and access keys decrypt and match their public keys",
            ));
        }
        Err(_) => findings.push(Finding::new(
            "keys",
            Severity::Problem,
            "a mesh key of this device is missing or does not decrypt",
            "this identity cannot be repaired: run `tethra mesh leave`, then pair this device \
             again with an invite from another device",
        )),
    }
    let seal_len: Option<i64> = conn
        .query_row(
            "SELECT length(wrapped_seal_key) FROM mesh_self WHERE id = 'self'",
            [],
            |r| r.get(0),
        )
        .ok();
    if seal_len.is_some_and(|n| n >= 32) {
        findings.push(Finding::ok(
            "sealing_key",
            "the sealing key is present (it is decrypted only to import a shared credential)",
        ));
    } else {
        findings.push(Finding::new(
            "sealing_key",
            Severity::Problem,
            "the sealing key is missing",
            "run `tethra mesh leave` and pair this device again",
        ));
    }

    // Items: every row's derived columns against its bytes.
    let mut rows = scan_items(conn)?;
    let unreadable = rows.iter().filter(|r| r.item.is_none()).count();
    let mismatched = rows
        .iter()
        .filter(|r| r.item.is_some() && !r.columns_match())
        .count();
    let rebuild_fix = "run `tethra mesh doctor --rebuild`; items it removes come back from a peer \
                       that holds them at the next exchange (repair)";
    let mut opened = identity::open_store(db_path, data_dir, Arc::new(super::clock::SystemClock));
    let mut rebuild = None;
    let mut unsigned = Vec::new();
    if let Ok(Some(store)) = &opened {
        let (bad, unknown) = unsigned_rows(&rows, store);
        unsigned = bad;
        if unknown > 0 {
            findings.push(Finding::new(
                "items",
                Severity::Warning,
                format!("{unknown} stored item(s) come from devices this roster does not know"),
                "these are kept and relayed; if the count grows, report it as a bug",
            ));
        }
    }
    if opts.rebuild && (unreadable > 0 || mismatched > 0 || !unsigned.is_empty()) {
        drop(opened);
        let r = rebuild_items(conn, &rows, &unsigned)?;
        rows = scan_items(conn)?;
        rebuild = Some(r);
        unsigned.clear();
        opened = identity::open_store(db_path, data_dir, Arc::new(super::clock::SystemClock));
        if let Ok(Some(store)) = &opened {
            unsigned = unsigned_rows(&rows, store).0;
        }
    } else if opts.rebuild {
        rebuild = Some(RebuildReport::default());
    }
    let unreadable = rows.iter().filter(|r| r.item.is_none()).count();
    let mismatched = rows
        .iter()
        .filter(|r| r.item.is_some() && !r.columns_match())
        .count();
    if unreadable == 0 && mismatched == 0 && unsigned.is_empty() {
        findings.push(Finding::ok(
            "items",
            format!(
                "{} stored item(s); each one's bytes, columns and signature agree",
                rows.len()
            ),
        ));
    } else {
        findings.push(Finding::new(
            "items",
            Severity::Problem,
            format!(
                "{unreadable} unreadable item row(s), {mismatched} row(s) whose columns disagree \
                 with their bytes, {} row(s) without a valid signature",
                unsigned.len()
            ),
            rebuild_fix,
        ));
    }

    let store = match opened {
        Ok(Some(store)) => store,
        Ok(None) | Err(_) => {
            findings.push(Finding::new(
                "store",
                Severity::Problem,
                "the mesh store does not load, so the node cannot start",
                rebuild_fix,
            ));
            return Ok(StoreDoctorReport {
                initialized: true,
                findings,
                rebuild,
            });
        }
    };

    // Marker and forks: the two reasons the node refuses to run.
    match store.marker_status() {
        Ok(MarkerStatus::Ok) => findings.push(Finding::ok(
            "marker",
            "the identity marker vouches for this database",
        )),
        Ok(status) => findings.push(Finding::new(
            "marker",
            Severity::Problem,
            format!(
                "the identity marker does not vouch for this database: {}",
                status.problem().unwrap_or(status.as_str())
            ),
            "this database is a copy or was rolled back; the node will not run on it. Run \
             `tethra mesh leave` and pair this device again",
        )),
        Err(_) => findings.push(Finding::new(
            "marker",
            Severity::Problem,
            "the identity marker cannot be read",
            "check the permissions of the `mesh` folder in the data directory; if the file is \
             gone, run `tethra mesh leave` and pair again",
        )),
    }
    let roster = &store.state().roster;
    if roster.fork_seq(&device).is_some() {
        findings.push(Finding::new(
            "fork",
            Severity::Problem,
            "another installation used this device's identity (a fork was reported)",
            "run `tethra mesh leave`, pair this device again, and remove the old identity from \
             another device",
        ));
    } else {
        let forked: Vec<String> = roster.forks().map(|(d, _)| short(d)).collect();
        if forked.is_empty() {
            findings.push(Finding::ok("fork", "no device has forked"));
        } else {
            findings.push(Finding::new(
                "fork",
                Severity::Warning,
                format!("forked device(s): {}", forked.join(", ")),
                "each forked device must leave and pair again; then remove its old identity \
                 with `tethra mesh remove`",
            ));
        }
    }

    // Dot log, VV and views against a fresh rebuild from the item rows.
    match store.verify_against_disk() {
        Ok(()) => findings.push(Finding::ok(
            "dot_log",
            "the version vector, dot log and chains are consistent",
        )),
        Err(_) => findings.push(Finding::new(
            "dot_log",
            Severity::Problem,
            "the dot log or version vector is inconsistent",
            "this is a storage bug or a damaged database: run `tethra mesh leave` and pair \
             again, and report it",
        )),
    }
    match store.rebuild_views() {
        Ok(rebuilt) if rebuilt == *store.state() => findings.push(Finding::ok(
            "views",
            "the views match a rebuild from the stored items",
        )),
        _ => findings.push(Finding::new(
            "views",
            Severity::Problem,
            "the views differ from a rebuild from the stored items",
            rebuild_fix,
        )),
    }

    let stats = store.stats();
    if stats.clock_skew.is_empty() {
        findings.push(Finding::ok("clock_skew", "no device's clock is flagged"));
    } else {
        let list: Vec<String> = stats
            .clock_skew
            .iter()
            .map(|(d, ms)| format!("{} by {} s", short(d), ms / 1000))
            .collect();
        findings.push(Finding::new(
            "clock_skew",
            Severity::Warning,
            format!(
                "clock(s) ahead of this device's by more than 60 s: {}",
                list.join(", ")
            ),
            "fix the system clock on those devices (enable automatic time); their edits can \
             win last-writer-wins conflicts they should not",
        ));
    }
    if stats.rejected_items == 0 {
        findings.push(Finding::ok("rejected", "no item has been rejected"));
    } else {
        findings.push(Finding::new(
            "rejected",
            Severity::Info,
            format!("{} item(s) were rejected at ingest", stats.rejected_items),
            "rejected items are never stored; a growing count means a peer runs a buggy or \
             incompatible build",
        ));
    }
    match store.rollback_hold() {
        None => findings.push(Finding::ok("rollback", "no rollback hold")),
        Some(held) => findings.push(Finding::new(
            "rollback",
            Severity::Warning,
            format!(
                "a peer holds this device's own items up to seq {held}, past what this database \
                 has; nothing is minted until they come back"
            ),
            "keep the node running so an exchange returns them; if the peer reporting it is \
             not trustworthy, remove it",
        )),
    }

    // Repair: a repair that changed state is a bug signal (PROTOCOL.md §8.5).
    let last = peers::last_repair(conn)?;
    let changed = stats.repairs_changed;
    let when = last
        .as_ref()
        .map(|r| format!("; last repair round {}", peers::ms_rfc3339(r.at_ms)))
        .unwrap_or_else(|| "; no repair round recorded yet".into());
    if changed == 0 && last.as_ref().is_none_or(|r| r.changed == 0) {
        findings.push(Finding::ok(
            "repair",
            format!("repair has never changed stored state{when}"),
        ));
    } else {
        findings.push(Finding::new(
            "repair",
            Severity::Warning,
            format!("repair changed stored state {changed} time(s){when}"),
            "honest replication never needs repair to change state: after a `--rebuild` this \
             is expected; otherwise report it as a bug",
        ));
    }
    let hellos = peers::hello_records(conn)?;
    let mismatched: Vec<String> = hellos
        .iter()
        .filter(|(_, h)| !h.digest_mismatches.is_empty())
        .map(|(d, h)| format!("{} ({} origin(s))", short(d), h.digest_mismatches.len()))
        .collect();
    if hellos.is_empty() {
        findings.push(Finding::ok(
            "digests",
            "no exchange recorded yet to compare digests with",
        ));
    } else if mismatched.is_empty() {
        findings.push(Finding::ok(
            "digests",
            format!(
                "at the last exchange with each of {} peer(s), every origin with equal version \
                 vectors had equal digests",
                hellos.len()
            ),
        ));
    } else {
        findings.push(Finding::new(
            "digests",
            Severity::Warning,
            format!(
                "digests differed at equal version vectors (repaired in that exchange): {}",
                mismatched.join(", ")
            ),
            "repair resolves this on its own; if it recurs with the same peer, run `tethra mesh \
             doctor` on that device too",
        ));
    }
    Ok(StoreDoctorReport {
        initialized: true,
        findings,
        rebuild,
    })
}
