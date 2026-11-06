//! The desktop's in-process node (Increment 09, DESIGN §D13 "Who runs the
//! node"): `NodeSupervisor` and `sync_with_settings`, the pieces the Tauri
//! app drives from its vault lifecycle (start after unlock, stop on every
//! lock path, shut down on exit).
//!
//! First with a fake node that watches the lock flag the supervisor hands it
//! (start, restart, lock, stop, shutdown, start errors, a node that stops by
//! itself), then with real nodes on 127.0.0.1:0 in temp data directories. No
//! discovery, no LAN address, fake keys only.

mod common;

use api_tracker_core::mesh::node_settings::NodeSettings;
use api_tracker_core::mesh::DeviceId;
use api_tracker_mesh::instance::{self, ControlTarget, NodeStatus, Response};
use api_tracker_mesh::runtime::{StopCondition, StopFlag, StopReason, StopReport};
use api_tracker_mesh::supervisor::{
    sync_with_settings, NodeSupervisor, StartOutcome, SupervisedNode,
};
use api_tracker_mesh::{NetError, NetResult};
use common::{device_id, genesis, vault, wait_for, Dev};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

// ------------------------------------------------------------- the fake node

/// The fake's shared state, as the supervisor and the control channel see it.
struct FakeControl {
    status: NodeStatus,
    stopping: AtomicBool,
    /// Why it stopped by itself (removed, left, forked), if it did.
    self_stop: Mutex<Option<StopReason>>,
    replicated: Mutex<Vec<Option<String>>>,
}

impl FakeControl {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            status: NodeStatus {
                pid: std::process::id(),
                device_id: DeviceId::from_bytes([0x5a; 16]),
                started_at: "2026-10-29T00:00:00Z".into(),
                listen: vec!["127.0.0.1:7700".into()],
                advertised: vec!["127.0.0.1:7700".into()],
                interval_ms: 30_000,
                discovery: false,
                rounds: 0,
                last_round_at: None,
                active_sessions: 0,
                hooks: Vec::new(),
                last_hook_error: None,
                last_publish_error: None,
                stopping: false,
            },
            stopping: AtomicBool::new(false),
            self_stop: Mutex::new(None),
            replicated: Mutex::new(Vec::new()),
        })
    }

    /// The node stops on its own, as a removed or forked node does.
    fn stop_by_itself(&self, why: StopReason) {
        *self.self_stop.lock().unwrap() = Some(why);
        self.stopping.store(true, Ordering::SeqCst);
    }
}

impl ControlTarget for FakeControl {
    fn status(&self) -> NodeStatus {
        let mut s = self.status.clone();
        s.stopping = self.stopping.load(Ordering::SeqCst);
        s
    }

    fn replicate_now(&self, peer: Option<String>, _repair: bool) -> Response {
        self.replicated.lock().unwrap().push(peer);
        Response::Replicated {
            exchanges: Vec::new(),
            repairs_changed: 0,
        }
    }

    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }
}

struct FakeNode {
    control: Arc<FakeControl>,
    lock: StopFlag,
    /// While set, the node keeps "finishing an exchange" after its stop.
    hold: Arc<AtomicBool>,
    /// Stands in for the node's keys: its last reference goes with the node.
    keys: Arc<[u8; 32]>,
}

impl SupervisedNode for FakeNode {
    fn control(&self) -> Arc<dyn ControlTarget> {
        self.control.clone()
    }

    fn wait(self: Box<Self>) -> StopReport {
        let mut lock = self.lock.clone();
        let reason = loop {
            if let Some(r) = lock.check() {
                break r;
            }
            if self.control.stopping.load(Ordering::SeqCst) {
                break self
                    .control
                    .self_stop
                    .lock()
                    .unwrap()
                    .unwrap_or(StopReason::Requested);
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        while self.hold.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(2));
        }
        let keys = Arc::downgrade(&self.keys);
        drop(self);
        StopReport {
            reason,
            keys_dropped: keys.upgrade().is_none(),
        }
    }
}

/// What the test keeps of a fake it started.
struct Fake {
    control: Arc<FakeControl>,
    /// The lock flag the supervisor handed to the start.
    lock: StopFlag,
    hold: Arc<AtomicBool>,
    keys: Weak<[u8; 32]>,
}

impl Fake {
    fn lock_raised(&self) -> bool {
        self.lock.clone().check() == Some(StopReason::Locked)
    }

    fn release(&self) {
        self.hold.store(false, Ordering::SeqCst);
    }
}

type Fakes = Arc<Mutex<Vec<Fake>>>;

/// A start function for `start_with` that records the fake it starts.
fn fake_start(
    fakes: &Fakes,
    hold: bool,
) -> impl FnOnce(StopFlag) -> NetResult<Box<dyn SupervisedNode>> {
    let fakes = fakes.clone();
    move |lock| {
        let control = FakeControl::new();
        let hold = Arc::new(AtomicBool::new(hold));
        let keys = Arc::new([0u8; 32]);
        fakes.lock().unwrap().push(Fake {
            control: control.clone(),
            lock: lock.clone(),
            hold: hold.clone(),
            keys: Arc::downgrade(&keys),
        });
        Ok(Box::new(FakeNode {
            control,
            lock,
            hold,
            keys,
        }) as Box<dyn SupervisedNode>)
    }
}

fn settings(listen: &[&str]) -> Option<NodeSettings> {
    Some(NodeSettings {
        run_while_open: true,
        listen: listen.iter().map(|a| (*a).to_owned()).collect(),
        all_interfaces: false,
        discover: false,
    })
}

/// Wait until the reaper recorded how the node stopped.
fn stopped(sup: &NodeSupervisor) -> api_tracker_mesh::supervisor::StopInfo {
    wait_for(5, || sup.state().last_stop.is_some(), "the node's stop");
    sup.state().last_stop.unwrap()
}

#[test]
fn a_start_runs_once_per_settings_and_new_settings_restart_the_node() {
    let sup = NodeSupervisor::new();
    let fakes = Fakes::default();
    let s1 = settings(&["127.0.0.1:7700"]);
    assert_eq!(
        sup.start_with(s1.clone(), fake_start(&fakes, false))
            .unwrap(),
        StartOutcome::Started
    );
    let st = sup.state();
    assert!(st.running.is_some() && st.last_error.is_none() && st.last_stop.is_none());
    assert!(sup.is_running());

    // The same settings: the running node stays, nothing new starts.
    assert_eq!(
        sup.start_with(s1, |_| panic!("a second node must not start"))
            .unwrap(),
        StartOutcome::AlreadyRunning
    );
    assert_eq!(fakes.lock().unwrap().len(), 1);

    // Different settings: the old node is stopped (and waited for) first.
    assert_eq!(
        sup.start_with(settings(&["127.0.0.1:7701"]), fake_start(&fakes, false))
            .unwrap(),
        StartOutcome::Started
    );
    let f = fakes.lock().unwrap();
    assert_eq!(f.len(), 2);
    assert!(f[0].control.stopping.load(Ordering::SeqCst));
    assert!(!f[0].lock_raised(), "a restart is not a lock");
    assert!(f[0].keys.upgrade().is_none(), "the old node is gone");
    let last = sup.state().last_stop.expect("the restart waited for it");
    assert_eq!(last.reason, StopReason::Requested);
    assert!(!f[1].control.stopping.load(Ordering::SeqCst));
    assert!(sup.is_running());
    drop(f);
    sup.shutdown(Duration::from_secs(5)).unwrap();
}

#[test]
fn a_lock_raises_the_flag_reaps_the_node_and_nothing_restarts() {
    let sup = NodeSupervisor::new();
    sup.lock(); // no node: nothing to do, no panic
    let fakes = Fakes::default();
    sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, false))
        .unwrap();
    let t = Instant::now();
    sup.lock();
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "lock() never waits for the node"
    );
    assert!(fakes.lock().unwrap()[0].lock_raised());
    let stop = stopped(&sup);
    assert_eq!(stop.reason, StopReason::Locked);
    assert_eq!(stop.description, "the vault locked");
    assert!(stop.keys_dropped);
    assert!(fakes.lock().unwrap()[0].keys.upgrade().is_none());
    wait_for(5, || !sup.state().stopping, "the reaper to finish");
    // Locked stays locked: nothing starts a node again but a new start
    // (after the next unlock).
    std::thread::sleep(Duration::from_millis(100));
    let st = sup.state();
    assert!(st.running.is_none() && !st.stopping);
    assert_eq!(fakes.lock().unwrap().len(), 1);
    assert!(sup.replicate_now(None, false).is_none());
    sup.lock(); // twice is harmless
    assert_eq!(sup.state().last_stop.unwrap().reason, StopReason::Locked);
}

#[test]
fn stop_and_stop_and_wait_end_the_node_and_a_start_waits_for_a_stopping_one() {
    let sup = NodeSupervisor::new();
    let fakes = Fakes::default();
    sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, false))
        .unwrap();
    sup.stop();
    assert_eq!(stopped(&sup).reason, StopReason::Requested);
    assert!(!fakes.lock().unwrap()[0].lock_raised());

    // A node still finishing an exchange: stop_and_wait reports it.
    sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, true))
        .unwrap();
    assert!(!sup.stop_and_wait(Duration::from_millis(50)));
    let st = sup.state();
    assert!(st.running.is_none(), "the node was handed to the reaper");
    assert!(st.stopping, "and is still finishing");
    fakes.lock().unwrap()[1].release();
    assert!(sup.stop_and_wait(Duration::from_secs(5)));
    assert!(!sup.state().stopping);
    assert!(sup.stop_and_wait(Duration::from_millis(1)), "none left");

    // A start after a stop waits for the old node (it may hold the port).
    sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, true))
        .unwrap();
    sup.stop();
    let releaser = {
        let fakes = fakes.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            fakes.lock().unwrap()[2].release();
        })
    };
    let t = Instant::now();
    assert_eq!(
        sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, false))
            .unwrap(),
        StartOutcome::Started
    );
    assert!(t.elapsed() >= Duration::from_millis(100), "it waited");
    assert!(fakes.lock().unwrap()[2].keys.upgrade().is_none());
    releaser.join().unwrap();
    sup.shutdown(Duration::from_secs(5)).unwrap();
}

#[test]
fn shutdown_locks_the_node_waits_for_it_and_reports_how_it_stopped() {
    let sup = NodeSupervisor::new();
    assert!(
        sup.shutdown(Duration::from_millis(10)).is_none(),
        "no node ever ran"
    );
    let fakes = Fakes::default();
    sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, false))
        .unwrap();
    let info = sup.shutdown(Duration::from_secs(5)).expect("in time");
    assert_eq!(info.reason, StopReason::Locked);
    assert!(info.keys_dropped);
    assert!(fakes.lock().unwrap()[0].lock_raised());
    assert!(!sup.state().stopping && sup.state().running.is_none());

    // Bounded: a node that does not finish in time does not hold the exit.
    sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, true))
        .unwrap();
    let t = Instant::now();
    assert!(sup.shutdown(Duration::from_millis(50)).is_none());
    assert!(t.elapsed() < Duration::from_secs(2));
    assert!(sup.state().stopping);
    fakes.lock().unwrap()[1].release();
    let info = sup.shutdown(Duration::from_secs(5)).expect("finished now");
    assert_eq!(info.reason, StopReason::Locked);
}

#[test]
fn a_start_error_is_recorded_returned_and_cleared_by_the_next_start() {
    let sup = NodeSupervisor::new();
    let err = sup
        .start_with(settings(&["127.0.0.1:7700"]), |_| {
            Err(NetError::Node("the listen address is already in use"))
        })
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "mesh node: the listen address is already in use"
    );
    let st = sup.state();
    assert_eq!(st.last_error.as_deref(), Some(err.to_string().as_str()));
    assert!(st.running.is_none() && !st.stopping);
    assert!(!sup.is_running());
    // Nothing to lock, stop or wait for: none of it panics.
    sup.lock();
    sup.stop();
    assert!(sup.stop_and_wait(Duration::from_millis(1)));
    assert!(sup.replicate_now(None, false).is_none());

    let fakes = Fakes::default();
    sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, false))
        .unwrap();
    assert!(sup.state().last_error.is_none(), "a good start clears it");
    sup.shutdown(Duration::from_secs(5)).unwrap();
}

#[test]
fn a_node_that_stopped_by_itself_is_reaped_when_the_state_is_read() {
    let sup = NodeSupervisor::new();
    let fakes = Fakes::default();
    sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, false))
        .unwrap();
    // Another device removed this one: the node says it is stopping.
    fakes.lock().unwrap()[0]
        .control
        .stop_by_itself(StopReason::Removed);
    assert!(sup.state().running.is_none(), "state() reaped it");
    let stop = stopped(&sup);
    assert_eq!(stop.reason, StopReason::Removed);
    assert!(stop.keys_dropped);
    assert!(!fakes.lock().unwrap()[0].lock_raised());
    assert!(sup.replicate_now(None, false).is_none());
    // It stays stopped; the next start (unlock, settings) starts a new one.
    assert_eq!(
        sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, false))
            .unwrap(),
        StartOutcome::Started
    );
    sup.shutdown(Duration::from_secs(5)).unwrap();
}

#[test]
fn replicate_now_runs_on_the_running_node_only() {
    let sup = NodeSupervisor::new();
    assert!(sup.replicate_now(None, false).is_none(), "no node here");
    let fakes = Fakes::default();
    sup.start_with(settings(&["127.0.0.1:7700"]), fake_start(&fakes, false))
        .unwrap();
    let r = sup.replicate_now(Some("127.0.0.1:7801".into()), false);
    assert!(matches!(r, Some(Response::Replicated { .. })), "{r:?}");
    assert_eq!(
        *fakes.lock().unwrap()[0].control.replicated.lock().unwrap(),
        vec![Some("127.0.0.1:7801".to_owned())]
    );
    sup.shutdown(Duration::from_secs(5)).unwrap();
}

// -------------------------------------------------------------- real nodes

/// "Run mesh while Tethra is open" on loopback: no reauthentication.
fn run_on_loopback(dev: &Dev) {
    let s = NodeSettings {
        run_while_open: true,
        listen: vec!["127.0.0.1:0".into()],
        all_interfaces: false,
        discover: false,
    };
    dev.vault.mesh_node_settings_set(None, &s).unwrap();
}

fn sync(sup: &NodeSupervisor, dev: &Dev) -> NetResult<StartOutcome> {
    sync_with_settings(sup, &dev.vault, &dev.paths.data_dir, None)
}

fn released(dev: &Dev) {
    wait_for(
        5,
        || instance::running_pid(&dev.paths.data_dir).is_none(),
        "the node to release the data directory",
    );
}

#[test]
fn a_real_node_starts_from_the_settings_and_a_lock_stops_it_and_drops_its_keys() {
    let dev = genesis("dev-a");
    let dir = dev.paths.data_dir.clone();
    run_on_loopback(&dev);
    let sup = NodeSupervisor::new();
    assert_eq!(sync(&sup, &dev).unwrap(), StartOutcome::Started);

    // It answers the data directory's control socket like `tethra mesh
    // serve` would, and publishes where a new device can pair.
    let st = instance::status(&dir).expect("the in-process node answers");
    assert_eq!(st.device_id, device_id(&dev));
    assert_eq!(st.pid, std::process::id(), "in this process");
    assert!(st.listen[0].starts_with("127.0.0.1:"), "{:?}", st.listen);
    assert!(!st.discovery);
    let running = sup.state().running.unwrap();
    assert_eq!(running.advertised, st.advertised);
    assert!(!running.advertised.is_empty());
    // A second sync with the same settings keeps it.
    assert_eq!(sync(&sup, &dev).unwrap(), StartOutcome::AlreadyRunning);
    // "Replicate now" goes to it: no peer yet, an empty round.
    match sup.replicate_now(None, false) {
        Some(Response::Replicated { exchanges, .. }) => assert!(exchanges.is_empty()),
        other => panic!("{other:?}"),
    }

    sup.lock();
    released(&dev);
    let stop = stopped(&sup);
    assert_eq!(stop.reason, StopReason::Locked);
    assert!(stop.keys_dropped, "every reference to its keys is gone");
    wait_for(5, || !sup.state().stopping, "the reaper to finish");
    std::thread::sleep(Duration::from_millis(150));
    assert!(sup.state().running.is_none());
    assert!(instance::running_pid(&dir).is_none(), "nothing restarted");
}

#[test]
fn sync_runs_nothing_outside_a_mesh_or_with_the_setting_off_and_stops_a_running_node() {
    let sup = NodeSupervisor::new();
    // Not in a mesh.
    let lone = vault();
    assert_eq!(sync(&sup, &lone).unwrap(), StartOutcome::Off);
    assert!(sup.state().running.is_none());
    assert!(instance::running_pid(&lone.paths.data_dir).is_none());
    // In a mesh, never turned on.
    let dev = genesis("dev-a");
    assert_eq!(sync(&sup, &dev).unwrap(), StartOutcome::Off);
    assert!(instance::running_pid(&dev.paths.data_dir).is_none());
    // Turned on, then off again (a narrowing: no password).
    run_on_loopback(&dev);
    assert_eq!(sync(&sup, &dev).unwrap(), StartOutcome::Started);
    assert!(instance::running_pid(&dev.paths.data_dir).is_some());
    let mut off = dev.vault.mesh_node_settings().unwrap();
    off.run_while_open = false;
    dev.vault.mesh_node_settings_set(None, &off).unwrap();
    assert_eq!(sync(&sup, &dev).unwrap(), StartOutcome::Off);
    released(&dev);
    let stop = stopped(&sup);
    assert_eq!(stop.reason, StopReason::Requested);
    assert!(stop.keys_dropped);
    assert!(sup.state().running.is_none());
}

#[test]
fn shutdown_on_exit_releases_the_data_directory_and_a_second_node_is_a_recorded_error() {
    let dev = genesis("dev-a");
    let dir = dev.paths.data_dir.clone();
    run_on_loopback(&dev);
    let sup = NodeSupervisor::new();
    assert_eq!(sync(&sup, &dev).unwrap(), StartOutcome::Started);

    // One node per data directory: another start fails, is recorded, and
    // leaves the first running.
    let other = NodeSupervisor::new();
    let err = sync(&other, &dev).unwrap_err();
    let st = other.state();
    assert_eq!(st.last_error, Some(err.to_string()));
    assert!(st.running.is_none());
    assert!(sup.is_running());

    let info = sup.shutdown(Duration::from_secs(5)).expect("in time");
    assert_eq!(info.reason, StopReason::Locked);
    assert!(info.keys_dropped);
    // Shutdown waited: the directory is free at once.
    assert!(instance::running_pid(&dir).is_none());
    assert_eq!(sync(&other, &dev).unwrap(), StartOutcome::Started);
    assert!(other.state().last_error.is_none());
    other.shutdown(Duration::from_secs(5)).unwrap();
    assert!(instance::running_pid(&dir).is_none());
}

/// The desktop's device workflow end to end, through the functions its
/// commands call (the manual run of Increment 09, without the window): the
/// app's in-process node answers a pairing invite that names its published
/// address, the new device shows up, the app removes it, and a lock stops
/// the node so `tethra mesh status` would say "not running".
#[test]
fn a_device_pairs_with_the_in_process_node_is_removed_and_the_lock_stops_the_node() {
    let app = genesis("app");
    let dir = app.paths.data_dir.clone();
    run_on_loopback(&app);
    let sup = NodeSupervisor::new();
    assert_eq!(sync(&sup, &app).unwrap(), StartOutcome::Started);

    // `mesh_invite_create`: the invite names what the running node publishes.
    let addrs = sup.state().running.unwrap().advertised;
    assert!(!addrs.is_empty());
    let inv = app
        .vault
        .mesh_invite_create(&common::master(), None)
        .unwrap();
    let text = api_tracker_core::mesh::invite::format_invite(&inv.token, &addrs).unwrap();

    // The new device (`tethra mesh join` / the desktop's Join) pairs with the
    // app's node and completes its first exchange.
    let laptop = vault();
    let report = common::join(&laptop, &text, "laptop").unwrap();
    assert!(report.exchange.aborted.is_none(), "{:?}", report.exchange);
    assert!(report.inviter_verified);
    let laptop_id = device_id(&laptop);

    // `mesh_devices` on the app lists it as an active member.
    let rows = app.vault.mesh_devices().unwrap();
    let row = rows.iter().find(|r| r.device_id == laptop_id).unwrap();
    assert!(row.active && !row.removed);
    assert_eq!(row.name.as_deref(), Some("laptop"));

    // `mesh_device_remove` (reauthenticated in core).
    let (removed, _epoch) = app
        .vault
        .mesh_device_remove(&common::master(), &laptop_id.to_hex())
        .unwrap();
    assert_eq!(removed, laptop_id);
    let rows = app.vault.mesh_devices().unwrap();
    assert!(rows.iter().any(|r| r.device_id == laptop_id && r.removed));

    // Lock: the node stops, drops its keys and frees the data directory.
    sup.lock();
    released(&app);
    let stop = stopped(&sup);
    assert_eq!(stop.reason, StopReason::Locked);
    assert!(stop.keys_dropped);
    assert!(
        instance::status(&dir).is_none(),
        "`mesh status` sees no node"
    );
}
