//! `tethra mesh doctor`: the store-side checks of core
//! (`core::mesh::doctor`: schema, keys, marker, forks, items, dot log,
//! views, skew, rejections, rollback, repair, digests), then the network
//! side: whether a node runs, whether its listeners accept connections from
//! this device, the peer table, and with `--repair` a repair round. Every
//! finding carries a plain-language fix.

use crate::error::NetResult;
use crate::instance::{self, Response};
use crate::node::{MeshNode, TransportLimits};
use crate::replicate::replicate_once;
use api_tracker_core::mesh::clock::Clock;
use api_tracker_core::mesh::doctor::{self as core_doctor, Finding, RebuildReport, Severity};
use api_tracker_core::mesh::peers::{self, RepairRecord};
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::vault::UnlockedVault;
use serde::Serialize;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default)]
pub struct DoctorOptions {
    pub rebuild: bool,
    pub repair: bool,
}

/// What a `--repair` round did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RepairSummary {
    /// Whether the running node ran it (otherwise this command did, one
    /// exchange per known peer address).
    pub via_node: bool,
    pub exchanges: u64,
    pub failed: u64,
    /// Times repair changed stored state (a bug signal unless after a
    /// `--rebuild`).
    pub changed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub initialized: bool,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebuild: Option<RebuildReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair: Option<RepairSummary>,
}

impl DoctorReport {
    /// The worst severity found.
    pub fn worst(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Ok)
    }
}

/// Whether something accepts TCP connections at `addr` from this device (an
/// unspecified address is probed on loopback). Only connects and closes.
fn accepts(addr: &str) -> bool {
    let Ok(mut sock) = addr.parse::<SocketAddr>() else {
        return false;
    };
    if sock.ip().is_unspecified() {
        sock.set_ip(if sock.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    TcpStream::connect_timeout(&sock, Duration::from_secs(2)).is_ok()
}

fn node_findings(data_dir: &Path, findings: &mut Vec<Finding>) -> bool {
    let Some(st) = instance::status(data_dir) else {
        if instance::running_pid(data_dir).is_some() {
            findings.push(Finding::new(
                "node",
                Severity::Warning,
                "a node answers on the control socket but its status is unreadable",
                "check that the `mesh/node.nonce` file is readable by you; restart the node",
            ));
            return true;
        }
        findings.push(Finding::new(
            "node",
            Severity::Info,
            "no mesh node is running on this device, so it replicates only when you run \
             `tethra mesh replicate`",
            "start one with `tethra mesh serve --listen ADDR:PORT` (see docs/mesh/USER_GUIDE.md)",
        ));
        return false;
    };
    findings.push(Finding::ok(
        "node",
        format!(
            "a node is running (pid {}), listening on {}; {} round(s) so far",
            st.pid,
            st.listen.join(", "),
            st.rounds
        ),
    ));
    let dead: Vec<&String> = st.listen.iter().filter(|a| !accepts(a)).collect();
    if dead.is_empty() {
        findings.push(Finding::ok(
            "listener",
            "every listener accepts connections from this device",
        ));
    } else {
        findings.push(Finding::new(
            "listener",
            Severity::Problem,
            format!(
                "listener(s) not accepting connections: {}",
                dead.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "restart the node; if it persists, another program may hold the port",
        ));
    }
    if let Some(e) = &st.last_publish_error {
        findings.push(Finding::new(
            "advertise",
            Severity::Warning,
            format!("the node could not publish its addresses: {e}"),
            "other devices keep using the addresses they knew; fix the cause above",
        ));
    }
    if let Some(e) = &st.last_hook_error {
        findings.push(Finding::new(
            "hooks",
            Severity::Warning,
            format!("a round hook failed: {e}"),
            "the node keeps replicating; the next round retries the hook",
        ));
    }
    true
}

fn peer_findings(vault: &UnlockedVault, findings: &mut Vec<Finding>) -> NetResult<Vec<String>> {
    let rows = vault.mesh_peers()?;
    if rows.is_empty() {
        findings.push(Finding::new(
            "peers",
            Severity::Warning,
            "no peer address is known, so a node has no one to dial",
            "add one with `tethra mesh peer add HOST:PORT` (another device's listen address); \
             others are then learned from the devices themselves",
        ));
        return Ok(Vec::new());
    }
    let failing: Vec<String> = rows
        .iter()
        .filter(|r| r.failures > 0)
        .map(|r| format!("{} ({} failure(s))", r.addr, r.failures))
        .collect();
    if failing.is_empty() {
        findings.push(Finding::ok(
            "peers",
            format!("{} peer address(es), none failing", rows.len()),
        ));
    } else {
        findings.push(Finding::new(
            "peers",
            Severity::Warning,
            format!("unreachable: {}", failing.join(", ")),
            "check that the device is on, its node is running, and the address is reachable \
             (same LAN, or the same VPN such as Tailscale)",
        ));
    }
    // From the vault's own connection: doctor must work on a store that no
    // longer loads.
    let changes = peers::device_changes(vault.connection())?;
    for c in changes {
        findings.push(Finding::new(
            "peers",
            Severity::Info,
            format!(
                "a different device ({}) answered at {} than before ({})",
                &c.to.to_hex()[..8],
                c.addr,
                &c.from.to_hex()[..8]
            ),
            "expected after that device paired again; otherwise check who uses that address",
        ));
    }
    Ok(rows.into_iter().map(|r| r.addr).collect())
}

/// One exchange with every known address, from this process, when no node
/// runs.
fn repair_one_shot(
    vault: &UnlockedVault,
    clock: Arc<dyn Clock>,
    addrs: &[String],
) -> NetResult<RepairSummary> {
    let node = MeshNode::open(vault, clock.clone(), TransportLimits::default())?;
    let before = node.store().stats().repairs_changed;
    let (mut ok, mut failed) = (0, 0);
    for a in addrs {
        match replicate_once(&node, a) {
            Ok(r) if r.aborted.is_none() => ok += 1,
            _ => failed += 1,
        }
    }
    let changed = node.store().stats().repairs_changed.saturating_sub(before);
    let store = node.store();
    peers::record_repair(
        store.connection(),
        &RepairRecord {
            at_ms: clock.now_ms(),
            exchanges: ok,
            changed,
        },
    )?;
    Ok(RepairSummary {
        via_node: false,
        exchanges: ok,
        failed,
        changed,
    })
}

pub fn run(
    vault: &UnlockedVault,
    data_dir: &Path,
    clock: Arc<dyn Clock>,
    opts: DoctorOptions,
) -> NetResult<DoctorReport> {
    let core = vault.mesh_doctor(core_doctor::DoctorOptions {
        rebuild: opts.rebuild,
    })?;
    let mut report = DoctorReport {
        initialized: core.initialized,
        findings: core.findings,
        rebuild: core.rebuild,
        repair: None,
    };
    if !report.initialized {
        return Ok(report);
    }
    let running = node_findings(data_dir, &mut report.findings);
    let addrs = peer_findings(vault, &mut report.findings)?;
    if opts.repair {
        let summary = if running {
            match instance::request(
                data_dir,
                |nonce| instance::Request::ReplicateNow {
                    nonce,
                    peer: None,
                    repair: true,
                },
                instance::REPLICATE_WAIT,
            )? {
                Response::Replicated {
                    exchanges,
                    repairs_changed,
                } => RepairSummary {
                    via_node: true,
                    exchanges: exchanges.iter().filter(|e| e.error.is_none()).count() as u64,
                    failed: exchanges.iter().filter(|e| e.error.is_some()).count() as u64,
                    changed: repairs_changed,
                },
                _ => RepairSummary {
                    via_node: true,
                    exchanges: 0,
                    failed: 0,
                    changed: 0,
                },
            }
        } else {
            repair_one_shot(vault, clock, &addrs)?
        };
        report.findings.push(if summary.changed == 0 {
            Finding::ok(
                "repair_round",
                format!(
                    "repair round: {} exchange(s), {} failed; nothing needed repair",
                    summary.exchanges, summary.failed
                ),
            )
        } else {
            Finding::new(
                "repair_round",
                Severity::Warning,
                format!(
                    "repair round: {} exchange(s); repair changed stored state {} time(s)",
                    summary.exchanges, summary.changed
                ),
                "expected right after `--rebuild` (it re-fetches removed items); otherwise a \
                 bug signal worth reporting",
            )
        });
        report.repair = Some(summary);
    }
    Ok(report)
}
