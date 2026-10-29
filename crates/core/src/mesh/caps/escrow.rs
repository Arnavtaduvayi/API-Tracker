//! The escrow fence (MESH-SI-10, DESIGN §D15): rights this device gives
//! away (a transfer, a burn, a reclaim grant) must never still be counted
//! as available by a gateway enforcing caps from a snapshot up to 5 s old.
//!
//! Every give is first a row of `mesh_cap_escrow` (local only, never
//! replicated):
//! - **Immediate** — cap enforcement is off on this device (the only case
//!   in Increment 07, where the gateway does not enforce), or the gateway is
//!   provably not running (a gateway that starts later reads the published
//!   transfer anyway): the `cap.rights` item is minted and the row written
//!   `published` in one transaction.
//! - **Await ack** — enforcement is on and the gateway is running: the row
//!   is written `pending` and nothing is published. The gateway deducts every
//!   `pending` and `acked` amount from its snapshot, then marks the rows it
//!   counted `acked` with its snapshot generation ([`ack`]). At its next
//!   round the node publishes each acked row, marking it `published` in the
//!   same transaction as the item. A row the gateway has not acknowledged
//!   within [`super::policy::ACK_WAIT_MS`] is reported as waiting and
//!   carried to later rounds. A row whose month ended, or that no longer
//!   fits what this device holds, is `cancelled`.
//!
//! While a row is open (`pending` or `acked`) its amount is reserved: this
//! device's own spendable figure leaves it out (`Ledger::local_avail`).

use crate::error::Result;
use crate::mesh::dot::CapId;
use crate::mesh::kinds::{Month, Recipient};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

/// Whether the gateway of this data directory is running. Core performs no
/// I/O to find out; the caller supplies the probe (the node uses the
/// gateway's control socket).
pub trait GatewayProbe {
    fn gateway_running(&self) -> bool;
}

/// A probe that always answers "not running" (tests, one-shot commands on
/// a device without a gateway).
pub struct AssumeNotRunning;

impl GatewayProbe for AssumeNotRunning {
    fn gateway_running(&self) -> bool {
        false
    }
}

/// A probe that always answers "running": the conservative answer when
/// liveness cannot be established (transfers then wait for an ack).
pub struct AssumeRunning;

impl GatewayProbe for AssumeRunning {
    fn gateway_running(&self) -> bool {
        true
    }
}

impl<F: Fn() -> bool> GatewayProbe for F {
    fn gateway_running(&self) -> bool {
        self()
    }
}

/// How a give is published.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fence {
    /// Publish now (enforcement off, or no gateway running).
    Immediate,
    /// Reserve now; publish after the running gateway's ack.
    AwaitAck,
}

/// Whether this device's gateway enforces caps
/// (`gateway_config.cap_enforcement`, local only; Increment 08 adds the
/// reauthenticated switch).
pub fn enforcement_on(conn: &Connection) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT cap_enforcement FROM gateway_config WHERE id = 'gateway'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some_and(|v| v == 1))
}

/// The port this data directory's gateway serves on, if one was ever
/// configured (the node's liveness probe on platforms without the control
/// socket).
pub fn gateway_port(conn: &Connection) -> Result<Option<u16>> {
    Ok(conn
        .query_row(
            "SELECT port FROM gateway_config WHERE id = 'gateway'",
            [],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten()
        .and_then(|p| u16::try_from(p).ok()))
}

pub fn fence(conn: &Connection, probe: &dyn GatewayProbe) -> Result<Fence> {
    Ok(if enforcement_on(conn)? && probe.gateway_running() {
        Fence::AwaitAck
    } else {
        Fence::Immediate
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowState {
    Pending,
    Acked,
    Published,
    Cancelled,
}

impl EscrowState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Acked => "acked",
            Self::Published => "published",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "acked" => Self::Acked,
            "published" => Self::Published,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EscrowRow {
    pub id: String,
    pub cap_id: CapId,
    pub month: Month,
    pub to: String,
    pub amount_micros: u64,
    pub state: EscrowState,
    pub acked_generation: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

impl EscrowRow {
    pub fn recipient(&self) -> Option<Recipient> {
        Recipient::parse(&self.to)
    }
}

fn i64_of(x: u64) -> i64 {
    i64::try_from(x).unwrap_or(i64::MAX)
}

/// Record a give. Returns the row id.
pub(crate) fn insert(
    conn: &Connection,
    cap: &CapId,
    month: Month,
    to: &Recipient,
    amount: u64,
    state: EscrowState,
    at: &str,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO mesh_cap_escrow (id, cap_id, month, to_device, amount_micros, state,
             acked_generation, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7)",
        params![
            id,
            cap.to_hex(),
            month.to_string(),
            to.to_string(),
            i64_of(amount),
            state.as_str(),
            at
        ],
    )?;
    Ok(id)
}

pub(crate) fn set_state(conn: &Connection, id: &str, state: EscrowState, at: &str) -> Result<()> {
    conn.execute(
        "UPDATE mesh_cap_escrow SET state = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, state.as_str(), at],
    )?;
    Ok(())
}

/// The amount reserved for `(cap, month)`: rows `pending` or `acked`.
pub fn open_amount(conn: &Connection, cap: &CapId, month: Month) -> Result<u64> {
    let v: i64 = conn.query_row(
        "SELECT COALESCE(SUM(amount_micros), 0) FROM mesh_cap_escrow
         WHERE cap_id = ?1 AND month = ?2 AND state IN ('pending', 'acked')",
        params![cap.to_hex(), month.to_string()],
        |r| r.get(0),
    )?;
    Ok(v.max(0) as u64)
}

/// The amount reserved for `(cap, month)` to one recipient.
pub fn open_amount_to(conn: &Connection, cap: &CapId, month: Month, to: &Recipient) -> Result<u64> {
    let v: i64 = conn.query_row(
        "SELECT COALESCE(SUM(amount_micros), 0) FROM mesh_cap_escrow
         WHERE cap_id = ?1 AND month = ?2 AND to_device = ?3 AND state IN ('pending', 'acked')",
        params![cap.to_hex(), month.to_string(), to.to_string()],
        |r| r.get(0),
    )?;
    Ok(v.max(0) as u64)
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<EscrowRow>> {
    let cap: String = r.get(1)?;
    let month: String = r.get(2)?;
    let state: String = r.get(5)?;
    let (Ok(cap_id), Some(month), Some(state)) = (
        CapId::parse(&cap),
        Month::parse(&month),
        EscrowState::parse(&state),
    ) else {
        return Ok(None);
    };
    Ok(Some(EscrowRow {
        id: r.get(0)?,
        cap_id,
        month,
        to: r.get(3)?,
        amount_micros: r.get::<_, i64>(4)?.max(0) as u64,
        state,
        acked_generation: r.get(6)?,
        created_at: r.get(7)?,
        updated_at: r.get(8)?,
    }))
}

const COLUMNS: &str = "id, cap_id, month, to_device, amount_micros, state, acked_generation, \
                       created_at, updated_at";

/// Every open row (`pending` or `acked`), oldest first.
pub fn open_rows(conn: &Connection) -> Result<Vec<EscrowRow>> {
    let mut st = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM mesh_cap_escrow WHERE state IN ('pending', 'acked')
         ORDER BY created_at, id"
    ))?;
    let rows = st.query_map([], row)?;
    let mut out = Vec::new();
    for r in rows {
        out.extend(r?);
    }
    Ok(out)
}

/// Every row, newest first, at most `limit` (status and tests).
pub fn rows(conn: &Connection, limit: usize) -> Result<Vec<EscrowRow>> {
    let mut st = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM mesh_cap_escrow ORDER BY created_at DESC, id DESC LIMIT ?1"
    ))?;
    let rows = st.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], row)?;
    let mut out = Vec::new();
    for r in rows {
        out.extend(r?);
    }
    Ok(out)
}

/// Forget closed rows (`published`, `cancelled`) of months before `month`:
/// the published item is the record, and an ended month's rights expired.
pub(crate) fn prune_before(conn: &Connection, month: Month) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM mesh_cap_escrow WHERE state IN ('published', 'cancelled') AND month < ?1",
        [month.to_string()],
    )?)
}

/// **The gateway's half of the fence** (Increment 08 calls it from its
/// poller): after it rebuilt its cap snapshot with every open escrow amount
/// deducted, it marks the `pending` rows that snapshot counted as `acked`
/// with the snapshot's generation. The node then publishes them. The
/// snapshot must read the cap items and the escrow rows in one read
/// transaction, or a row published between the two reads would be counted
/// by neither. Returns the number of rows acknowledged.
pub fn ack(conn: &Connection, ids: &[String], generation: i64) -> Result<usize> {
    let at = crate::clock::now_rfc3339();
    let mut n = 0;
    for id in ids {
        n += conn.execute(
            "UPDATE mesh_cap_escrow SET state = 'acked', acked_generation = ?2, updated_at = ?3
             WHERE id = ?1 AND state = 'pending'",
            params![id, generation, at],
        )?;
    }
    Ok(n)
}
