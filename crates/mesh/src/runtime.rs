//! The node runtime (Increment 05, DESIGN §D13): a long-running node that
//! keeps every reachable peer converged on its own.
//!
//! [`RunningNode::start`] claims the data directory (one node per data
//! directory, [`crate::instance`]), binds the listeners, and starts three
//! threads beside the caller's:
//! - **serve**: the accept loop ([`crate::serve::serve`]);
//! - **control**: the local control channel (`status`, `replicate-now`,
//!   `stop`), which never holds the node or its keys;
//! - **main**: the outbound loop. Every `interval` (30 s by default, ±20%
//!   jitter from an injected seed) and at once on `replicate-now`, it runs a
//!   **round**:
//!   1. the **round hooks**, in order (none in Increment 05; 06 adds the usage
//!      publisher, 07 the cap reconciler); a hook error is reported in
//!      `status` and does not stop the round;
//!   2. publishes this node's listen addresses in `device.info` if they
//!      changed (address gossip);
//!   3. refreshes the learned peer addresses: gossip from other active
//!      devices' `device.info`, and mDNS sightings tagged for this mesh;
//!   4. exchanges once with every eligible peer (backoff, [`crate::peers`]),
//!      at most `max_outbound` (4) at a time and within the node's 8 session
//!      slots, recording every dial in `mesh_peers`;
//!   5. once a day (and on `doctor --repair`) records the round as a repair
//!      round: every exchange compares per-origin digests and repairs
//!      (PROTOCOL.md §8.5), so the record says whether repair changed state.
//!
//! **Key lifetime (MESH-SI-7).** The node's keys live only in the
//! [`MeshNode`], which only the serve and main threads (and their exchanges)
//! hold. A [`StopCondition`] ends the node: the CLI session expiring or being
//! locked ([`SessionAlive`]), an opted-in maximum runtime ([`Deadline`]), a
//! desktop lock signal ([`StopFlag`]), or `stop` on the control channel. On
//! stop the listeners close, running exchanges finish (bounded by the
//! session limits), every thread is joined, and the last reference to the
//! node drops, which zeroizes its keys. [`StopReport::keys_dropped`] states
//! that it happened. The node also stops itself if this device left the
//! mesh, was removed, or forked.

use crate::discover::{self, Discovery};
use crate::error::{NetError, NetResult};
use crate::instance::{self, ControlServer, ControlTarget, ExchangeSummary, NodeStatus, Response};
use crate::node::MeshNode;
use crate::peers::{self, Jitter, Scheduler, Target};
use crate::replicate::replicate_once;
use crate::serve::{bind_all, serve};
use api_tracker_core::mesh::clock::Clock;
use api_tracker_core::mesh::identity;
use api_tracker_core::mesh::kinds::{Day, MAX_LISTEN_ADDRS};
use api_tracker_core::mesh::membership;
use api_tracker_core::mesh::peers::{self as peer_table, AttemptOutcome, PeerSource, RepairRecord};
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::session::{peek_session_id, peek_state, SessionFileState};
use api_tracker_core::CoreError;
use serde::Serialize;
use std::collections::{BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How often the node re-reads its stop condition and its identity (the
/// session file, the marker): fast enough to stop within a tenth of a
/// second, without a file read per loop turn.
const CHECK_EVERY: Duration = Duration::from_millis(100);
const IDENTITY_EVERY: Duration = Duration::from_secs(1);

/// Work that runs before every round (DESIGN §D14, §D15): the usage
/// publisher (06) and the cap reconciler (07) plug in here. A hook may mint
/// through `node.store()` and `node.keys()`; a mint during a rollback hold
/// or on an untrusted identity is refused by the store, which the hook
/// should treat as "not now" ([`crate::session::is_mint_refusal`]).
pub trait RoundHook: Send + Sync {
    fn name(&self) -> &'static str;
    fn before_round(&self, node: &MeshNode) -> NetResult<()>;
}

/// Why a node stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// `stop` on the control channel, or the owner's stop flag.
    Requested,
    /// The CLI session was locked (its file deleted or replaced).
    SessionEnded,
    /// The CLI session expired (auto-lock).
    SessionExpired,
    /// The maximum runtime the user opted into elapsed.
    Deadline,
    /// The desktop app locked (Increment 09).
    Locked,
    /// This device's identity forked; it must leave and pair again.
    Forked,
    /// Another device removed this one.
    Removed,
    /// This device left the mesh (its mesh rows are gone).
    Left,
}

impl StopReason {
    pub fn describe(&self) -> &'static str {
        match self {
            StopReason::Requested => "stop requested",
            StopReason::SessionEnded => "the vault session was locked",
            StopReason::SessionExpired => "the vault session expired (auto-lock)",
            StopReason::Deadline => "the maximum runtime elapsed",
            StopReason::Locked => "the vault locked",
            StopReason::Forked => "this device's mesh identity forked",
            StopReason::Removed => "this device was removed from the mesh",
            StopReason::Left => "this device left the mesh",
        }
    }
}

/// When the node must stop. Checked between rounds and while a round's
/// exchanges run (every ~100 ms).
pub trait StopCondition: Send {
    fn check(&mut self) -> Option<StopReason>;
}

/// Never stops on its own (`serve` with `TETHRA_PASSWORD` and no maximum
/// runtime: until Ctrl-C or `tethra mesh stop`).
pub struct Never;

impl StopCondition for Never {
    fn check(&mut self) -> Option<StopReason> {
        None
    }
}

/// Stops while the CLI session the node started from is alive no more: its
/// `session.json` was deleted (`tethra lock`), expired (auto-lock, never
/// refreshed by the node), or replaced by another session.
pub struct SessionAlive {
    path: PathBuf,
    id: Option<String>,
}

impl SessionAlive {
    pub fn new(session_path: &Path) -> Self {
        Self {
            path: session_path.to_path_buf(),
            id: peek_session_id(session_path),
        }
    }
}

impl StopCondition for SessionAlive {
    fn check(&mut self) -> Option<StopReason> {
        match peek_state(&self.path) {
            SessionFileState::Missing => Some(StopReason::SessionEnded),
            SessionFileState::Expired => Some(StopReason::SessionExpired),
            SessionFileState::Active => {
                let now = peek_session_id(&self.path);
                (now.is_some() && now != self.id).then_some(StopReason::SessionEnded)
            }
        }
    }
}

/// Stops at `at_ms` on `clock` (an opted-in maximum runtime).
pub struct Deadline {
    clock: Arc<dyn Clock>,
    at_ms: u64,
}

impl Deadline {
    pub fn after(clock: Arc<dyn Clock>, runtime: Duration) -> Self {
        let at_ms = clock
            .now_ms()
            .saturating_add(u64::try_from(runtime.as_millis()).unwrap_or(u64::MAX));
        Self { clock, at_ms }
    }
}

impl StopCondition for Deadline {
    fn check(&mut self) -> Option<StopReason> {
        (self.clock.now_ms() >= self.at_ms).then_some(StopReason::Deadline)
    }
}

/// A flag another thread raises (the desktop's lock signal, a test).
#[derive(Clone)]
pub struct StopFlag {
    flag: Arc<AtomicBool>,
    reason: StopReason,
}

impl StopFlag {
    pub fn new(reason: StopReason) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            reason,
        }
    }

    pub fn raise(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

impl StopCondition for StopFlag {
    fn check(&mut self) -> Option<StopReason> {
        self.flag.load(Ordering::SeqCst).then_some(self.reason)
    }
}

/// Stops when any of its conditions does.
pub struct AnyOf(pub Vec<Box<dyn StopCondition>>);

impl StopCondition for AnyOf {
    fn check(&mut self) -> Option<StopReason> {
        self.0.iter_mut().find_map(|c| c.check())
    }
}

/// Where a node reports events.
pub type NodeLog = Arc<dyn Fn(&str) + Send + Sync>;

/// How a node runs.
pub struct NodeConfig {
    /// Addresses to listen on (only through `bind::bind_listener`).
    pub listen: Vec<SocketAddr>,
    /// Allow `0.0.0.0` / `[::]` (`--all-interfaces`).
    pub all_interfaces: bool,
    /// Addresses to publish instead of the bound ones (`--advertise`).
    pub advertise: Vec<String>,
    pub interval: Duration,
    pub max_outbound: usize,
    /// How often a round is recorded as a repair round.
    pub repair_interval: Duration,
    pub discovery: Option<Arc<dyn Discovery>>,
    pub hooks: Vec<Arc<dyn RoundHook>>,
    pub jitter: Jitter,
    /// Where the node reports events (a peer changed device, a hook
    /// failed). Static text and ids only.
    pub log: Option<NodeLog>,
}

impl NodeConfig {
    pub fn new(listen: Vec<SocketAddr>) -> Self {
        Self {
            listen,
            all_interfaces: false,
            advertise: Vec::new(),
            interval: Duration::from_secs(30),
            max_outbound: 4,
            repair_interval: Duration::from_secs(24 * 60 * 60),
            discovery: None,
            hooks: Vec::new(),
            jitter: Jitter::from_os(),
            log: None,
        }
    }
}

/// What a stopped node reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StopReport {
    pub reason: StopReason,
    /// Every reference to the node is gone, so its keys were zeroized.
    pub keys_dropped: bool,
}

enum Command {
    ReplicateNow {
        peer: Option<String>,
        repair: bool,
        reply: mpsc::Sender<Response>,
    },
}

/// What the control channel and the owner see; holds no keys.
struct Shared {
    status: Mutex<NodeStatus>,
    stopping: AtomicBool,
    sessions: Arc<AtomicUsize>,
    commands: Mutex<mpsc::Sender<Command>>,
    log: Option<NodeLog>,
}

impl Shared {
    fn update(&self, f: impl FnOnce(&mut NodeStatus)) {
        f(&mut self.status.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn log(&self, msg: &str) {
        if let Some(l) = &self.log {
            l(msg);
        }
    }
}

impl ControlTarget for Shared {
    fn status(&self) -> NodeStatus {
        let mut s = self
            .status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        s.active_sessions = self.sessions.load(Ordering::SeqCst);
        s.stopping = self.stopping.load(Ordering::SeqCst);
        s
    }

    fn replicate_now(&self, peer: Option<String>, repair: bool) -> Response {
        let peer = match peer.map(|p| peer_table::normalize_addr(&p)) {
            Some(Err(_)) => {
                return Response::Error {
                    code: "invalid_input".into(),
                    message: "a peer address must be HOST:PORT".into(),
                }
            }
            Some(Ok(p)) => Some(p),
            None => None,
        };
        let (tx, rx) = mpsc::channel();
        let sent = self
            .commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(Command::ReplicateNow {
                peer,
                repair,
                reply: tx,
            });
        let stopping = || Response::Error {
            code: "stopping".into(),
            message: "the node is stopping".into(),
        };
        if sent.is_err() {
            return stopping();
        }
        rx.recv_timeout(instance::REPLICATE_WAIT - Duration::from_secs(5))
            .unwrap_or_else(|_| stopping())
    }

    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }
}

/// A started node. [`Self::wait`] blocks until it stops.
pub struct RunningNode {
    shared: Arc<Shared>,
    main: Option<JoinHandle<StopReason>>,
    serve: Option<JoinHandle<()>>,
    control: Option<ControlServer>,
    weak: Weak<MeshNode>,
    listen: Vec<SocketAddr>,
}

fn bind_error(e: &std::io::Error) -> NetError {
    match e.kind() {
        std::io::ErrorKind::InvalidInput => NetError::Node(
            "refusing to listen on every interface; pass --all-interfaces to allow it",
        ),
        std::io::ErrorKind::AddrInUse => NetError::Node("the listen address is already in use"),
        std::io::ErrorKind::AddrNotAvailable => {
            NetError::Node("the listen address is not an address of this machine")
        }
        _ => NetError::Node("the listen address cannot be bound"),
    }
}

/// The addresses to publish: `--advertise` if given; otherwise each bound
/// address, with an unspecified one (`--all-interfaces`) expanded to this
/// machine's non-loopback interface addresses on the bound port.
pub fn advertised_addrs(explicit: &[String], bound: &[SocketAddr]) -> Vec<String> {
    let mut out: Vec<String> = if explicit.is_empty() {
        let ifaces = if bound.iter().any(|b| b.ip().is_unspecified()) {
            if_addrs::get_if_addrs().unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut v = Vec::new();
        for b in bound {
            if !b.ip().is_unspecified() {
                v.push(b.to_string());
                continue;
            }
            for i in &ifaces {
                let ip = i.ip();
                let usable = !ip.is_loopback()
                    && match ip {
                        IpAddr::V4(a) => !a.is_link_local(),
                        // Link-local IPv6 needs a scope id peers cannot use.
                        IpAddr::V6(a) => (a.segments()[0] & 0xffc0) != 0xfe80,
                    };
                // `0.0.0.0` accepts IPv4 only; `[::]` usually both.
                if usable && (b.is_ipv6() || ip.is_ipv4()) {
                    v.push(SocketAddr::new(ip, b.port()).to_string());
                }
            }
        }
        v
    } else {
        explicit.to_vec()
    };
    let mut seen = BTreeSet::new();
    out.retain(|a| seen.insert(a.clone()));
    out.truncate(MAX_LISTEN_ADDRS);
    out
}

fn now_rfc(clock: &dyn Clock) -> String {
    peer_table::ms_rfc3339(clock.now_ms())
}

impl RunningNode {
    /// Claim the data directory, bind, and start. Fails if another node
    /// runs for `data_dir`, or a listen address cannot be bound.
    pub fn start(
        node: MeshNode,
        data_dir: &Path,
        config: NodeConfig,
        stop: Box<dyn StopCondition>,
    ) -> NetResult<Self> {
        for a in &config.advertise {
            peer_table::normalize_addr(a)?;
        }
        if config.listen.is_empty() {
            return Err(NetError::Node("give at least one --listen address"));
        }
        let claim = instance::claim(data_dir)?;
        let listeners = match bind_all(&config.listen, config.all_interfaces) {
            Ok(l) => l,
            Err(e) => {
                claim.release();
                return Err(bind_error(&e));
            }
        };
        let listen: Vec<SocketAddr> = listeners
            .iter()
            .map(|l| l.local_addr())
            .collect::<std::io::Result<_>>()?;
        let advertised = advertised_addrs(&config.advertise, &listen);
        let node = Arc::new(node);
        let weak = Arc::downgrade(&node);
        let (tx, rx) = mpsc::channel();
        let status = NodeStatus {
            pid: std::process::id(),
            device_id: node.self_id(),
            started_at: now_rfc(node.clock().as_ref()),
            listen: listen.iter().map(ToString::to_string).collect(),
            advertised: advertised.clone(),
            interval_ms: u64::try_from(config.interval.as_millis()).unwrap_or(u64::MAX),
            discovery: config.discovery.is_some(),
            rounds: 0,
            last_round_at: None,
            active_sessions: 0,
            hooks: config.hooks.iter().map(|h| h.name().to_owned()).collect(),
            last_hook_error: None,
            last_publish_error: None,
            stopping: false,
        };
        let shared = Arc::new(Shared {
            status: Mutex::new(status),
            stopping: AtomicBool::new(false),
            sessions: node.session_counter(),
            commands: Mutex::new(tx),
            log: config.log.clone(),
        });
        let serve_handle = {
            let (n, sh) = (node.clone(), shared.clone());
            std::thread::Builder::new()
                .name("tethra-mesh-serve".into())
                .spawn(move || {
                    let _ = serve(n, listeners, &|| sh.stopping.load(Ordering::SeqCst));
                })
                .map_err(|_| NetError::Node("the accept thread cannot start"))?
        };
        let control = match ControlServer::start(claim, shared.clone()) {
            Ok(c) => c,
            Err(e) => {
                shared.stopping.store(true, Ordering::SeqCst);
                let _ = serve_handle.join();
                return Err(e);
            }
        };
        let main = {
            let sh = shared.clone();
            let port = listen.first().map_or(0, SocketAddr::port);
            std::thread::Builder::new()
                .name("tethra-mesh-node".into())
                .spawn(move || {
                    let mut lp = Loop {
                        node,
                        shared: sh,
                        sched: Mutex::new(Scheduler::new(config.jitter.clone())),
                        jitter: config.jitter.clone(),
                        advertised,
                        port,
                        announced: None,
                        config,
                        stop,
                    };
                    let reason = lp.run(rx);
                    lp.shared.stopping.store(true, Ordering::SeqCst);
                    reason
                })
                .map_err(|_| NetError::Node("the node thread cannot start"))?
        };
        Ok(Self {
            shared,
            main: Some(main),
            serve: Some(serve_handle),
            control: Some(control),
            weak,
            listen,
        })
    }

    /// The addresses the listeners are bound to.
    pub fn listen_addrs(&self) -> &[SocketAddr] {
        &self.listen
    }

    pub fn status(&self) -> NodeStatus {
        self.shared.status()
    }

    /// Ask the node to stop; [`Self::wait`] returns once it has.
    pub fn stop(&self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
    }

    /// Run a round now (all peers, ignoring backoff, or one address).
    pub fn replicate_now(&self, peer: Option<String>, repair: bool) -> Response {
        self.shared.replicate_now(peer, repair)
    }

    /// Wait for the node to stop, join every thread, and report whether the
    /// keys were dropped.
    pub fn wait(mut self) -> StopReport {
        let reason = self
            .main
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or(StopReason::Requested);
        self.shared.stopping.store(true, Ordering::SeqCst);
        if let Some(h) = self.serve.take() {
            let _ = h.join();
        }
        if let Some(mut c) = self.control.take() {
            c.stop();
        }
        StopReport {
            reason,
            keys_dropped: self.weak.upgrade().is_none(),
        }
    }
}

impl Drop for RunningNode {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        if let Some(h) = self.main.take() {
            let _ = h.join();
        }
        if let Some(h) = self.serve.take() {
            let _ = h.join();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Eligibility {
    /// Scheduled: only peers out of backoff.
    Due,
    /// Forced: every peer.
    All,
}

struct Loop {
    node: Arc<MeshNode>,
    shared: Arc<Shared>,
    sched: Mutex<Scheduler>,
    jitter: Jitter,
    advertised: Vec<String>,
    port: u16,
    announced: Option<Day>,
    config: NodeConfig,
    stop: Box<dyn StopCondition>,
}

struct RoundOutcome {
    exchanges: Vec<ExchangeSummary>,
    repairs_changed: u64,
}

impl Loop {
    fn check_stop(&mut self) -> Option<StopReason> {
        if self.shared.stopping.load(Ordering::SeqCst) {
            return Some(StopReason::Requested);
        }
        let r = self.stop.check();
        if r.is_some() {
            self.shared.stopping.store(true, Ordering::SeqCst);
        }
        r
    }

    fn run(&mut self, rx: mpsc::Receiver<Command>) -> StopReason {
        let clock = self.node.clock().clone();
        let interval = u64::try_from(self.config.interval.as_millis()).unwrap_or(u64::MAX);
        let repair_every =
            u64::try_from(self.config.repair_interval.as_millis()).unwrap_or(u64::MAX);
        let mut next_round = 0u64;
        let mut identity_checked: Option<Instant> = None;
        loop {
            if let Some(r) = self.check_stop() {
                return r;
            }
            if identity_checked.is_none_or(|t| t.elapsed() >= IDENTITY_EVERY) {
                if let Some(r) = self.identity_stop() {
                    return r;
                }
                identity_checked = Some(Instant::now());
            }
            match rx.recv_timeout(CHECK_EVERY) {
                Ok(Command::ReplicateNow {
                    peer,
                    repair,
                    reply,
                }) => {
                    let out = self.round(Eligibility::All, peer, repair);
                    let _ = reply.send(Response::Replicated {
                        exchanges: out.exchanges,
                        repairs_changed: out.repairs_changed,
                    });
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return StopReason::Requested,
            }
            let now = clock.now_ms();
            if now >= next_round {
                let last_repair = {
                    let store = self.node.store();
                    peer_table::last_repair_ms(store.connection())
                };
                let repair = now.saturating_sub(last_repair) >= repair_every;
                self.round(Eligibility::Due, None, repair);
                next_round = clock.now_ms().saturating_add(self.jitter.spread(interval));
            }
        }
    }

    /// Stop when this device left, was removed, forked, or its marker no
    /// longer vouches for the database.
    fn identity_stop(&self) -> Option<StopReason> {
        let store = self.node.store();
        match membership::mesh_of(store.connection()) {
            Ok(None) => return Some(StopReason::Left),
            Ok(Some((mesh, _))) if mesh != self.node.mesh_id() => return Some(StopReason::Left),
            _ => {}
        }
        let me = self.node.self_id();
        if store.state().roster.is_removed(&me) {
            return Some(StopReason::Removed);
        }
        if identity::preflight(&store).is_err() {
            return Some(StopReason::Forked);
        }
        None
    }

    fn round(&mut self, which: Eligibility, peer: Option<String>, repair: bool) -> RoundOutcome {
        let clock = self.node.clock().clone();
        let now = clock.now_ms();
        for h in &self.config.hooks {
            if let Err(e) = h.before_round(&self.node) {
                let msg = format!("{}: {}", h.name(), e.log_text());
                self.shared.log(&format!("round hook failed: {msg}"));
                self.shared.update(|s| s.last_hook_error = Some(msg));
            }
        }
        self.publish_addresses();
        self.refresh_sources(now);
        let targets: Vec<Target> = match peer {
            Some(addr) => vec![Target {
                device: None,
                addrs: vec![addr],
            }],
            None => {
                let store = self.node.store();
                let rows = peer_table::list(store.connection()).unwrap_or_default();
                let mut sched = self.sched.lock().unwrap_or_else(PoisonError::into_inner);
                sched.retain(&rows);
                let eligible: Vec<_> = rows
                    .into_iter()
                    .filter(|r| which == Eligibility::All || sched.due(r, now))
                    .collect();
                peers::targets(&eligible, &store)
            }
        };
        let before = self.node.store().stats().repairs_changed;
        let exchanges = self.exchange_all(targets);
        let repairs_changed = self
            .node
            .store()
            .stats()
            .repairs_changed
            .saturating_sub(before);
        if repair {
            let rec = RepairRecord {
                at_ms: now,
                exchanges: exchanges.iter().filter(|e| e.error.is_none()).count() as u64,
                changed: repairs_changed,
            };
            let store = self.node.store();
            let _ = peer_table::record_repair(store.connection(), &rec);
        }
        let at = now_rfc(clock.as_ref());
        self.shared.update(|s| {
            s.rounds += 1;
            s.last_round_at = Some(at);
        });
        RoundOutcome {
            exchanges,
            repairs_changed,
        }
    }

    fn publish_addresses(&self) {
        let result = {
            let mut store = self.node.store();
            membership::publish_listen_addrs(
                &mut store,
                self.node.keys().signing_key(),
                &self.advertised,
            )
        };
        let err = match result {
            Ok(_) => None,
            Err(CoreError::Mesh(e)) => Some(e.to_string()),
            Err(_) => Some("local storage error".to_owned()),
        };
        self.shared.update(|s| s.last_publish_error = err);
    }

    fn refresh_sources(&mut self, now: u64) {
        {
            let store = self.node.store();
            let gossip = peers::gossip_addrs(&store, &self.advertised);
            let _ = peer_table::sync_learned(store.connection(), PeerSource::Gossip, &gossip);
        }
        let Some(d) = self.config.discovery.clone() else {
            return;
        };
        let Ok(keys) = self.node.access_keys() else {
            return;
        };
        let day = Day::from_unix_ms(now);
        if self.announced != Some(day) {
            let ips: Vec<IpAddr> = self
                .advertised
                .iter()
                .filter_map(|a| a.parse::<SocketAddr>().ok())
                .map(|s| s.ip())
                .collect();
            let txt = discover::txt(keys.current.1.expose(), now);
            if d.announce(self.port, &ips, &txt).is_ok() {
                self.announced = Some(day);
            }
        }
        let mut accept: Vec<&[u8; 32]> = vec![keys.current.1.expose()];
        if let Some((_, k)) = &keys.previous {
            accept.push(k.expose());
        }
        let found: BTreeSet<String> = d
            .browse()
            .into_iter()
            .filter(|s| discover::recognises(s, &accept, now))
            .flat_map(|s| s.addrs.into_iter().map(|a| a.to_string()))
            .filter(|a| !self.advertised.contains(a))
            .take(64)
            .collect();
        let store = self.node.store();
        let _ = peer_table::sync_learned(store.connection(), PeerSource::Mdns, &found);
    }

    /// Exchange with every target, at most `max_outbound` at a time, while
    /// still checking the stop condition.
    fn exchange_all(&mut self, targets: Vec<Target>) -> Vec<ExchangeSummary> {
        if targets.is_empty() {
            return Vec::new();
        }
        let workers = self.config.max_outbound.clamp(1, targets.len());
        let queue = Mutex::new(VecDeque::from(targets));
        let results = Mutex::new(Vec::new());
        let remaining = AtomicUsize::new(workers);
        let (node, shared, sched) = (&self.node, &self.shared, &self.sched);
        let mut stop_seen = None;
        let mut checked = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    work(node, shared, sched, &queue, &results);
                    remaining.fetch_sub(1, Ordering::SeqCst);
                });
            }
            while remaining.load(Ordering::SeqCst) > 0 {
                if stop_seen.is_none() && checked.elapsed() >= CHECK_EVERY {
                    checked = Instant::now();
                    stop_seen = self.stop.check();
                    if stop_seen.is_some() {
                        shared.stopping.store(true, Ordering::SeqCst);
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        results.into_inner().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One outbound worker: take targets until none are left or the node stops.
fn work(
    node: &MeshNode,
    shared: &Shared,
    sched: &Mutex<Scheduler>,
    queue: &Mutex<VecDeque<Target>>,
    results: &Mutex<Vec<ExchangeSummary>>,
) {
    loop {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let Some(target) = queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
        else {
            return;
        };
        for addr in target.addrs {
            if shared.stopping.load(Ordering::SeqCst) {
                return;
            }
            let Some(slot) = node.try_session() else {
                // Busy is not the peer's fault: no failure is recorded.
                results
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(ExchangeSummary {
                        addr,
                        device: target.device,
                        items_in: 0,
                        items_out: 0,
                        duration_ms: 0,
                        error: Some("every session slot is busy".into()),
                    });
                break;
            };
            let r = replicate_once(node, &addr);
            drop(slot);
            let at = node.clock().now_ms();
            let outcome = match &r {
                Ok(rep) => AttemptOutcome::Reached(rep.peer),
                Err(e) => AttemptOutcome::Failed(e.log_text()),
            };
            let failures = {
                let store = node.store();
                if let Ok(Some(c)) =
                    peer_table::record_attempt(store.connection(), &addr, at, outcome)
                {
                    shared.log(&format!(
                        "a different device answers at {}: {} (was {})",
                        c.addr,
                        &c.to.to_hex()[..8],
                        &c.from.to_hex()[..8]
                    ));
                }
                peer_table::get(store.connection(), &addr)
                    .ok()
                    .flatten()
                    .map_or(0, |p| p.failures)
            };
            sched
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .record(&addr, failures, at);
            let reached = r.is_ok();
            let summary = match r {
                Ok(rep) => ExchangeSummary {
                    addr,
                    device: Some(rep.peer),
                    items_in: rep.items_in,
                    items_out: rep.items_out,
                    duration_ms: rep.duration_ms,
                    error: rep.aborted.map(str::to_owned),
                },
                Err(e) => ExchangeSummary {
                    addr,
                    device: target.device,
                    items_in: 0,
                    items_out: 0,
                    duration_ms: 0,
                    error: Some(e.log_text().to_owned()),
                },
            };
            results
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(summary);
            if reached {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_advertised_addresses_win_and_concrete_binds_publish_themselves() {
        let bound: Vec<SocketAddr> = vec!["127.0.0.1:7420".parse().unwrap()];
        assert_eq!(advertised_addrs(&[], &bound), ["127.0.0.1:7420"]);
        let explicit = vec!["laptop.tail1.ts.net:7420".to_owned()];
        assert_eq!(advertised_addrs(&explicit, &bound), explicit);
    }

    #[test]
    fn an_every_interface_bind_publishes_concrete_non_loopback_addresses() {
        let bound: Vec<SocketAddr> = vec![SocketAddr::from(([0, 0, 0, 0], 7420))];
        for a in advertised_addrs(&[], &bound) {
            let s: SocketAddr = a.parse().unwrap();
            assert!(!s.ip().is_unspecified() && !s.ip().is_loopback(), "{a}");
            assert!(s.is_ipv4() && s.port() == 7420, "{a}");
        }
    }

    #[test]
    fn a_session_file_that_disappears_expires_or_changes_stops_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let write = |id: &str, exp: &str| {
            std::fs::write(
                &path,
                format!(
                    "{{\"session_id\":\"{id}\",\"created_at\":\"2026-01-01T00:00:00Z\",\
                     \"expires_at\":{exp},\"ttl_minutes\":15,\"payload_b64\":\"AA==\"}}"
                ),
            )
            .unwrap();
        };
        write("s1", "\"2999-01-01T00:00:00Z\"");
        let mut c = SessionAlive::new(&path);
        assert_eq!(c.check(), None);
        write("s2", "\"2999-01-01T00:00:00Z\"");
        assert_eq!(c.check(), Some(StopReason::SessionEnded));
        let mut c = SessionAlive::new(&path);
        write("s2", "\"2000-01-01T00:00:00Z\"");
        assert_eq!(c.check(), Some(StopReason::SessionExpired));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(c.check(), Some(StopReason::SessionEnded));
    }

    #[test]
    fn a_deadline_and_a_flag_stop_and_any_of_takes_the_first() {
        let clock = Arc::new(api_tracker_core::mesh::clock::ManualClock::new(1_000));
        let mut d = Deadline::after(clock.clone(), Duration::from_secs(5));
        assert_eq!(d.check(), None);
        clock.advance(5_000);
        assert_eq!(d.check(), Some(StopReason::Deadline));
        let flag = StopFlag::new(StopReason::Locked);
        let mut any = AnyOf(vec![Box::new(Never), Box::new(flag.clone())]);
        assert_eq!(any.check(), None);
        flag.raise();
        assert_eq!(any.check(), Some(StopReason::Locked));
    }
}
