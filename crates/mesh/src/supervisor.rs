//! The desktop's in-process node (Increment 09, DESIGN §D13 "Who runs the
//! node").
//!
//! The desktop runs the mesh node **on threads inside the app**, not as a
//! child process (unlike its foreground gateway): the keys never travel
//! through an environment variable or a session file. A [`NodeSupervisor`]
//! owns at most one node and is driven from the app's vault lifecycle:
//! - [`sync_with_settings`] after every unlock and every change of the
//!   local node settings (`core::mesh::node_settings`): starts the node when
//!   "Run mesh while Tethra is open" is on, restarts it when the settings it
//!   runs with changed, stops it when the setting is off;
//! - [`NodeSupervisor::lock`] on every lock path (explicit, auto-lock,
//!   restore): raises the node's lock flag ([`StopReason::Locked`]) and
//!   returns at once; a reaper thread joins the node, whose last reference
//!   then drops and zeroizes its keys (MESH-SI-7);
//! - [`NodeSupervisor::shutdown`] on app exit: the same, waiting (bounded)
//!   for the node to finish.
//!
//! Starting needs an `&UnlockedVault`, so a locked app cannot start a node;
//! the desktop starts it while it holds the unlocked vault, so a lock that
//! follows always finds it. Failures never panic: the last start error and
//! how the last node stopped are kept for `mesh_status`.

use crate::discover::MdnsDiscovery;
use crate::error::{NetError, NetResult};
use crate::instance::{ControlTarget, NodeStatus, Response};
use crate::node::{MeshNode, TransportLimits};
use crate::runtime::{NodeConfig, NodeLog, RunningNode, StopFlag, StopReason, StopReport};
use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::membership;
use api_tracker_core::mesh::node_settings::NodeSettings;
use api_tracker_core::mesh::peers::ms_rfc3339;
use api_tracker_core::vault::UnlockedVault;
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long a start waits for the previous node to finish stopping.
pub const STOP_WAIT: Duration = Duration::from_secs(10);

/// A node the supervisor can own: [`RunningNode`], or a fake in tests.
pub trait SupervisedNode: Send {
    /// The node's shared state: status, replicate-now, stop. Holds no keys.
    fn control(&self) -> Arc<dyn ControlTarget>;
    /// Block until the node has stopped and every thread is joined.
    fn wait(self: Box<Self>) -> StopReport;
}

impl SupervisedNode for RunningNode {
    fn control(&self) -> Arc<dyn ControlTarget> {
        RunningNode::control(self)
    }

    fn wait(self: Box<Self>) -> StopReport {
        RunningNode::wait(*self)
    }
}

/// How the last node stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StopInfo {
    pub reason: StopReason,
    pub description: &'static str,
    /// Every reference to the node is gone, so its keys were zeroized.
    pub keys_dropped: bool,
    pub at: String,
}

/// What `mesh_status` shows about the in-process node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SupervisorState {
    /// The running node's status (`None` when no node runs in this app).
    pub running: Option<NodeStatus>,
    /// A node is still finishing its exchanges after a stop.
    pub stopping: bool,
    /// Why the last start failed, if it did (static text and addresses).
    pub last_error: Option<String>,
    pub last_stop: Option<StopInfo>,
}

/// What a start did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartOutcome {
    Started,
    /// A node with the same settings was already running.
    AlreadyRunning,
    /// The settings say not to run (or this device is not in a mesh); any
    /// running node was stopped.
    Off,
}

struct Current {
    node: Box<dyn SupervisedNode>,
    control: Arc<dyn ControlTarget>,
    lock: StopFlag,
    settings: Option<NodeSettings>,
}

#[derive(Default)]
struct Inner {
    current: Option<Current>,
    reaper: Option<JoinHandle<()>>,
    last_error: Option<String>,
}

/// Owns the app's one in-process node.
pub struct NodeSupervisor {
    inner: Mutex<Inner>,
    last_stop: Arc<Mutex<Option<StopInfo>>>,
    clock: Arc<dyn Clock>,
}

impl Default for NodeSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeSupervisor {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            last_stop: Arc::new(Mutex::new(None)),
            clock,
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hand the current node to a reaper thread that joins it. Never
    /// blocks on the node.
    fn reap(&self, inner: &mut Inner) {
        let Some(cur) = inner.current.take() else {
            return;
        };
        let (last, clock) = (self.last_stop.clone(), self.clock.clone());
        let previous = inner.reaper.take();
        let spawned = std::thread::Builder::new()
            .name("tethra-mesh-reaper".into())
            .spawn(move || {
                if let Some(p) = previous {
                    let _ = p.join();
                }
                let report = cur.node.wait();
                *last.lock().unwrap_or_else(PoisonError::into_inner) = Some(StopInfo {
                    reason: report.reason,
                    description: report.reason.describe(),
                    keys_dropped: report.keys_dropped,
                    at: ms_rfc3339(clock.now_ms()),
                });
            });
        match spawned {
            Ok(h) => inner.reaper = Some(h),
            // No thread: nothing joins the node, but its stop was already
            // signalled and it ends on its own.
            Err(_) => inner.last_error = Some("the mesh node's stop could not be tracked".into()),
        }
    }

    /// Wait for a stopping node, at most `timeout`. True when none is left.
    fn wait_reaper(inner: &mut Inner, timeout: Duration) -> bool {
        let Some(h) = inner.reaper.as_ref() else {
            return true;
        };
        let until = Instant::now() + timeout;
        while !h.is_finished() {
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Some(h) = inner.reaper.take() {
            let _ = h.join();
        }
        true
    }

    /// A node that stopped by itself (left, removed, forked, or `tethra mesh
    /// stop` on its control channel) is reaped here.
    fn reap_if_stopped(&self, inner: &mut Inner) {
        if inner
            .current
            .as_ref()
            .is_some_and(|c| c.control.status().stopping)
        {
            self.reap(inner);
        }
    }

    /// Start a node with `start` unless one runs with the same `settings`
    /// (a different one is stopped first). `start` receives the lock flag to
    /// use as (part of) the node's stop condition. A failure is recorded for
    /// [`Self::state`] and returned.
    pub fn start_with(
        &self,
        settings: Option<NodeSettings>,
        start: impl FnOnce(StopFlag) -> NetResult<Box<dyn SupervisedNode>>,
    ) -> NetResult<StartOutcome> {
        let mut inner = self.inner();
        self.reap_if_stopped(&mut inner);
        if let Some(cur) = inner.current.as_ref() {
            if cur.settings == settings {
                return Ok(StartOutcome::AlreadyRunning);
            }
            cur.control.stop();
            self.reap(&mut inner);
        }
        if !Self::wait_reaper(&mut inner, STOP_WAIT) {
            let e = NetError::Node("the previous mesh node is still stopping; try again shortly");
            inner.last_error = Some(e.to_string());
            return Err(e);
        }
        let lock = StopFlag::new(StopReason::Locked);
        match start(lock.clone()) {
            Ok(node) => {
                let control = node.control();
                inner.current = Some(Current {
                    node,
                    control,
                    lock,
                    settings,
                });
                inner.last_error = None;
                Ok(StartOutcome::Started)
            }
            Err(e) => {
                inner.last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// The vault locked: signal the node and return without waiting.
    pub fn lock(&self) {
        let mut inner = self.inner();
        if let Some(cur) = inner.current.as_ref() {
            cur.lock.raise();
        }
        self.reap(&mut inner);
    }

    /// Stop the node (the setting was turned off) without waiting.
    pub fn stop(&self) {
        let mut inner = self.inner();
        if let Some(cur) = inner.current.as_ref() {
            cur.control.stop();
        }
        self.reap(&mut inner);
    }

    /// Stop the node and wait for it, at most `timeout` (before `leave`
    /// wipes the rows the node writes). True when no node is left.
    pub fn stop_and_wait(&self, timeout: Duration) -> bool {
        let mut inner = self.inner();
        if let Some(cur) = inner.current.as_ref() {
            cur.control.stop();
        }
        self.reap(&mut inner);
        Self::wait_reaper(&mut inner, timeout)
    }

    /// The app is exiting: lock the node and wait for it, at most
    /// `timeout`. Returns how it stopped, if it finished in time.
    pub fn shutdown(&self, timeout: Duration) -> Option<StopInfo> {
        let mut inner = self.inner();
        if let Some(cur) = inner.current.as_ref() {
            cur.lock.raise();
        }
        self.reap(&mut inner);
        if Self::wait_reaper(&mut inner, timeout) {
            self.last_stop
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        } else {
            None
        }
    }

    pub fn state(&self) -> SupervisorState {
        let mut inner = self.inner();
        self.reap_if_stopped(&mut inner);
        let stopping = inner.reaper.as_ref().is_some_and(|h| !h.is_finished());
        SupervisorState {
            running: inner.current.as_ref().map(|c| c.control.status()),
            stopping,
            last_error: inner.last_error.clone(),
            last_stop: self
                .last_stop
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }
    }

    /// Whether a node runs in this app.
    pub fn is_running(&self) -> bool {
        self.state().running.is_some()
    }

    /// Run a round now on the in-process node (`None`: no node runs here).
    /// The supervisor's lock is not held while the round runs.
    pub fn replicate_now(&self, peer: Option<String>, repair: bool) -> Option<Response> {
        let control = {
            let mut inner = self.inner();
            self.reap_if_stopped(&mut inner);
            inner.current.as_ref().map(|c| c.control.clone())
        }?;
        Some(control.replicate_now(peer, repair))
    }
}

/// Bring the in-process node in line with this device's node settings:
/// start it, restart it with changed settings, or stop it. Called after an
/// unlock and after the settings change. A device that is not in a mesh
/// runs no node.
pub fn sync_with_settings(
    sup: &NodeSupervisor,
    vault: &UnlockedVault,
    data_dir: &Path,
    log: Option<NodeLog>,
) -> NetResult<StartOutcome> {
    if membership::mesh_of(vault.connection())?.is_none() {
        sup.stop();
        return Ok(StartOutcome::Off);
    }
    let settings = vault.mesh_node_settings()?;
    if !settings.run_while_open {
        sup.stop();
        return Ok(StartOutcome::Off);
    }
    let cfg_settings = settings.clone();
    sup.start_with(Some(settings), move |lock| {
        let node = MeshNode::open(vault, Arc::new(SystemClock), TransportLimits::default())?;
        let mut cfg = NodeConfig::new(cfg_settings.listen_addrs());
        cfg.all_interfaces = cfg_settings.all_interfaces;
        if cfg_settings.discover {
            cfg.discovery = Some(Arc::new(MdnsDiscovery::new()?));
        }
        cfg.hooks = crate::hooks::default_hooks();
        cfg.log = log;
        let running = RunningNode::start(node, data_dir, cfg, Box::new(lock))?;
        Ok(Box::new(running) as Box<dyn SupervisedNode>)
    })
}
