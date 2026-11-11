//! One node per data directory, and its local control channel (DESIGN §D13).
//! Modelled on the gateway's control socket (`crates/gateway/src/control.rs`).
//!
//! - **Unix.** `<data-dir>/mesh/node.sock`, a 0600 socket in the 0700
//!   `mesh/` directory. Binding it is the single-instance lock: a live
//!   socket means another node owns the data directory; a stale one (no
//!   listener) is replaced. The socket's and directory's modes and owner are
//!   re-checked on every accept, so a permission loosened underneath the
//!   node stops the channel instead of widening it. As in the gateway, there
//!   is no peer-credential check (that needs `unsafe` or a new dependency);
//!   the kernel's permission check on the 0600 socket in a 0700 directory
//!   keeps other local users out, and same-user processes are inside the
//!   trust model.
//! - **Windows** (compiled and unit-tested in CI, runtime untested, like the
//!   gateway's, ADR 0019 D8): a loopback TCP listener on an ephemeral port,
//!   written to the nonce file. A live node answering `Health` on the
//!   recorded port is the single-instance check.
//! - **Nonce.** A per-boot random value in `node.nonce` (0600). Every request
//!   but `Health` must carry it: only a process that can read the file can
//!   drive the node. It is compared in constant time.
//!
//! One JSON request per line, at most 8 KiB: `Health`, `Status`,
//! `ReplicateNow { peer?, repair }` and `Stop`. The control channel never
//! touches keys: its target ([`ControlTarget`]) is the runtime's shared
//! status, not the [`crate::MeshNode`].

use crate::error::{NetError, NetResult};
use api_tracker_core::mesh::marker;
use api_tracker_core::mesh::DeviceId;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use zeroize::Zeroizing;

pub const SOCKET_NAME: &str = "node.sock";
pub const NONCE_NAME: &str = "node.nonce";
/// The largest request line.
pub const MAX_REQUEST: usize = 8 * 1024;
/// Control connections served at once.
const MAX_CONTROL_CONNECTIONS: usize = 4;
/// How long `ReplicateNow` may take before the client gives up waiting.
pub const REPLICATE_WAIT: Duration = Duration::from_secs(180);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const ALREADY_RUNNING: &str = "another Tethra Mesh node is already running for this data directory";

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness only; needs no nonce and reveals only the pid.
    Health,
    Status {
        nonce: String,
    },
    /// Run an exchange now: with `peer`, with that address only; otherwise
    /// with every peer, ignoring backoff. `repair` records it as a repair
    /// round (`doctor --repair`).
    ReplicateNow {
        nonce: String,
        #[serde(default)]
        peer: Option<String>,
        #[serde(default)]
        repair: bool,
    },
    Stop {
        nonce: String,
    },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op = match self {
            Request::Health => "Health",
            Request::Status { .. } => "Status",
            Request::ReplicateNow { .. } => "ReplicateNow",
            Request::Stop { .. } => "Stop",
        };
        write!(f, "Request::{op} {{ nonce: [REDACTED] }}")
    }
}

/// What a running node reports about itself. No key material, no nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub pid: u32,
    pub device_id: DeviceId,
    pub started_at: String,
    /// The addresses its listeners are bound to.
    pub listen: Vec<String>,
    /// The addresses it publishes in its `device.info`.
    pub advertised: Vec<String>,
    pub interval_ms: u64,
    pub discovery: bool,
    pub rounds: u64,
    pub last_round_at: Option<String>,
    pub active_sessions: usize,
    /// The round hooks it runs before each round (Increment 06 and later).
    pub hooks: Vec<String>,
    pub last_hook_error: Option<String>,
    /// Why it could not publish its addresses, if it could not.
    pub last_publish_error: Option<String>,
    pub stopping: bool,
}

/// One exchange of a `ReplicateNow`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeSummary {
    pub addr: String,
    pub device: Option<DeviceId>,
    pub items_in: u64,
    pub items_out: u64,
    pub duration_ms: u64,
    /// A static description when the dial or the exchange failed.
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Health {
        pid: u32,
    },
    Status(NodeStatus),
    Replicated {
        exchanges: Vec<ExchangeSummary>,
        /// How many times repair changed stored state during the round.
        repairs_changed: u64,
    },
    Error {
        code: String,
        message: String,
    },
}

/// What the control channel drives (the runtime's shared state).
pub trait ControlTarget: Send + Sync {
    fn status(&self) -> NodeStatus;
    fn replicate_now(&self, peer: Option<String>, repair: bool) -> Response;
    fn stop(&self);
}

/// Answer one request. The nonce is compared in constant time (BLAKE3
/// hashes compare in constant time).
pub fn dispatch(target: &dyn ControlTarget, expected_nonce: &str, request: Request) -> Response {
    let authorized = |given: &str| -> bool {
        blake3::hash(given.as_bytes()) == blake3::hash(expected_nonce.as_bytes())
    };
    let denied = || Response::Error {
        code: "unauthorized".into(),
        message: "the control nonce did not match this node".into(),
    };
    match request {
        Request::Health => Response::Health {
            pid: std::process::id(),
        },
        Request::Status { nonce } if authorized(&nonce) => Response::Status(target.status()),
        Request::ReplicateNow {
            nonce,
            peer,
            repair,
        } if authorized(&nonce) => target.replicate_now(peer, repair),
        Request::Stop { nonce } if authorized(&nonce) => {
            target.stop();
            Response::Ok
        }
        _ => denied(),
    }
}

/// Serve one accepted connection: one bounded line in, one line out.
pub fn serve_stream<S: Read + Write>(
    stream: S,
    target: &dyn ControlTarget,
    expected_nonce: &str,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    {
        let mut limited = (&mut reader).take(MAX_REQUEST as u64);
        limited.read_line(&mut line)?;
    }
    let response = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) => dispatch(target, expected_nonce, req),
        Err(_) => Response::Error {
            code: "invalid_input".into(),
            message: "unparseable control request".into(),
        },
    };
    let mut out = serde_json::to_string(&response).unwrap_or_else(|_| {
        "{\"result\":\"error\",\"code\":\"internal\",\"message\":\"\"}".to_owned()
    });
    out.push('\n');
    let mut stream = reader.into_inner();
    stream.write_all(out.as_bytes())?;
    stream.flush()
}

#[derive(Serialize, Deserialize)]
struct NonceFile {
    nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn mesh_dir(data_dir: &Path) -> NetResult<PathBuf> {
    let dir = marker::mesh_dir(data_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|_| NetError::Node("the mesh directory cannot be created"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| NetError::Node("the mesh directory cannot be restricted"))?;
    }
    Ok(dir)
}

/// Write a 0600 file, never through a planted symlink.
fn write_private(path: &Path, contents: &[u8]) -> NetResult<()> {
    if std::fs::symlink_metadata(path).is_ok() {
        std::fs::remove_file(path)
            .map_err(|_| NetError::Node("the nonce file cannot be replaced"))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|_| NetError::Node("the nonce file cannot be written"))?;
    f.write_all(contents)
        .and_then(|()| f.flush())
        .map_err(|_| NetError::Node("the nonce file cannot be written"))
}

fn read_nonce_file(data_dir: &Path) -> Option<NonceFile> {
    let raw = std::fs::read_to_string(marker::mesh_dir(data_dir).join(NONCE_NAME)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// The running node's nonce, if this process can read it.
pub fn read_nonce(data_dir: &Path) -> Option<Zeroizing<String>> {
    read_nonce_file(data_dir).map(|f| Zeroizing::new(f.nonce))
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};

    pub type Listener = UnixListener;
    pub type Stream = UnixStream;

    /// A Unix-socket path longer than this fails deep inside bind (104
    /// bytes on macOS, 108 on Linux).
    const MAX_SOCKET_PATH: usize = 100;

    pub fn socket_path(data_dir: &Path) -> PathBuf {
        marker::mesh_dir(data_dir).join(SOCKET_NAME)
    }

    /// The socket and its directory still admit only their owner.
    pub fn still_restricted(path: &Path) -> bool {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return false;
        };
        if meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
            return false;
        }
        let Some(dir) = path.parent().and_then(|d| std::fs::metadata(d).ok()) else {
            return false;
        };
        dir.permissions().mode() & 0o077 == 0 && dir.uid() == meta.uid()
    }

    pub fn claim(data_dir: &Path) -> NetResult<(Listener, Option<u16>)> {
        let path = socket_path(data_dir);
        if path.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(NetError::Node(
                "the data directory path is too long for the node's control socket; use a \
                 shorter TETHRA_DIR",
            ));
        }
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return Err(NetError::Node(
                    "the control socket path is a symlink; refusing to bind it",
                ));
            }
            if UnixStream::connect(&path).is_ok() {
                return Err(NetError::Node(ALREADY_RUNNING));
            }
            // A stale socket from a node that is gone.
            let _ = std::fs::remove_file(&path);
        }
        let listener = crate::bind::bind_control_socket(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                NetError::Node(ALREADY_RUNNING)
            } else {
                NetError::Node("the control socket cannot be bound")
            }
        })?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| NetError::Node("the control socket cannot be restricted"))?;
        }
        if !still_restricted(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(NetError::Node(
                "the control socket is not owner-only; refusing to serve it",
            ));
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| NetError::Node("the control socket cannot be configured"))?;
        Ok((listener, None))
    }

    pub fn accept(l: &Listener, data_dir: &Path) -> std::io::Result<Option<Stream>> {
        match l.accept() {
            Ok((s, _)) => {
                if !still_restricted(&socket_path(data_dir)) {
                    return Ok(None);
                }
                Ok(Some(s))
            }
            Err(e) => Err(e),
        }
    }

    pub fn connect(data_dir: &Path) -> std::io::Result<Stream> {
        UnixStream::connect(socket_path(data_dir))
    }

    pub fn cleanup(data_dir: &Path) {
        let _ = std::fs::remove_file(socket_path(data_dir));
    }
}

#[cfg(not(unix))]
mod platform {
    use super::*;
    use std::net::{SocketAddr, TcpListener, TcpStream};

    pub type Listener = TcpListener;
    pub type Stream = TcpStream;

    fn live_port(data_dir: &Path) -> Option<u16> {
        let port = read_nonce_file(data_dir)?.port?;
        let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).ok()?;
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        s.write_all(b"{\"op\":\"health\"}\n").ok()?;
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).ok()?;
        matches!(
            serde_json::from_str::<Response>(line.trim()),
            Ok(Response::Health { .. })
        )
        .then_some(port)
    }

    pub fn claim(data_dir: &Path) -> NetResult<(Listener, Option<u16>)> {
        if live_port(data_dir).is_some() {
            return Err(NetError::Node(ALREADY_RUNNING));
        }
        let l = crate::bind::bind_control_loopback()
            .map_err(|_| NetError::Node("the control listener cannot be bound"))?;
        let port = l
            .local_addr()
            .map_err(|_| NetError::Node("the control listener has no address"))?
            .port();
        l.set_nonblocking(true)
            .map_err(|_| NetError::Node("the control listener cannot be configured"))?;
        Ok((l, Some(port)))
    }

    pub fn accept(l: &Listener, _data_dir: &Path) -> std::io::Result<Option<Stream>> {
        l.accept().map(|(s, _)| Some(s))
    }

    pub fn connect(data_dir: &Path) -> std::io::Result<Stream> {
        let port = read_nonce_file(data_dir)
            .and_then(|f| f.port)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        TcpStream::connect_timeout(
            &SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
            IO_TIMEOUT,
        )
    }

    pub fn cleanup(_data_dir: &Path) {}
}

/// The single-instance claim, held from before the node binds anything
/// until it stops.
pub struct InstanceClaim {
    listener: platform::Listener,
    data_dir: PathBuf,
    nonce: Zeroizing<String>,
}

impl std::fmt::Debug for InstanceClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceClaim")
            .field("data_dir", &self.data_dir)
            .finish_non_exhaustive()
    }
}

/// Claim `data_dir` for one node: bind the control channel (the lock) and
/// write a fresh nonce. Fails if a node already runs there.
pub fn claim(data_dir: &Path) -> NetResult<InstanceClaim> {
    let dir = mesh_dir(data_dir)?;
    let (listener, port) = platform::claim(data_dir)?;
    let nonce = Zeroizing::new(hex(&api_tracker_core::crypto::random_bytes(16)));
    let file = Zeroizing::new(
        serde_json::to_string(&NonceFile {
            nonce: nonce.to_string(),
            port,
        })
        .map_err(|_| NetError::Node("the nonce file cannot be encoded"))?,
    );
    if let Err(e) = write_private(&dir.join(NONCE_NAME), file.as_bytes()) {
        platform::cleanup(data_dir);
        return Err(e);
    }
    Ok(InstanceClaim {
        listener,
        data_dir: data_dir.to_path_buf(),
        nonce,
    })
}

impl InstanceClaim {
    /// Give the claim up without serving (the node failed to start): remove
    /// the socket and the nonce file.
    pub fn release(self) {
        let dir = self.data_dir.clone();
        drop(self);
        platform::cleanup(&dir);
        let _ = std::fs::remove_file(marker::mesh_dir(&dir).join(NONCE_NAME));
    }
}

/// The control channel's accept thread. Dropping it stops serving and
/// removes the socket and nonce file.
pub struct ControlServer {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    data_dir: PathBuf,
}

impl ControlServer {
    pub fn start(claim: InstanceClaim, target: Arc<dyn ControlTarget>) -> NetResult<Self> {
        let InstanceClaim {
            listener,
            data_dir,
            nonce,
        } = claim;
        let stop = Arc::new(AtomicBool::new(false));
        let (stop2, dir2) = (stop.clone(), data_dir.clone());
        let active = Arc::new(AtomicUsize::new(0));
        let handle = std::thread::Builder::new()
            .name("tethra-mesh-control".into())
            .spawn(move || {
                let nonce: Arc<Zeroizing<String>> = Arc::new(nonce);
                while !stop2.load(Ordering::SeqCst) {
                    match platform::accept(&listener, &dir2) {
                        Ok(Some(stream)) => {
                            if active.load(Ordering::SeqCst) >= MAX_CONTROL_CONNECTIONS {
                                continue;
                            }
                            // An accepted socket inherits the listener's
                            // non-blocking flag on BSD/macOS.
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                            active.fetch_add(1, Ordering::SeqCst);
                            let (t, n, a) = (target.clone(), nonce.clone(), active.clone());
                            std::thread::spawn(move || {
                                let _ = serve_stream(stream, t.as_ref(), &n);
                                a.fetch_sub(1, Ordering::SeqCst);
                            });
                        }
                        Ok(None) => {}
                        Err(_) => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
            })
            .map_err(|_| NetError::Node("the control thread cannot start"))?;
        Ok(Self {
            stop,
            handle: Some(handle),
            data_dir,
        })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        platform::cleanup(&self.data_dir);
        let _ = std::fs::remove_file(marker::mesh_dir(&self.data_dir).join(NONCE_NAME));
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Send one request to the node of `data_dir` and read its answer.
pub fn send(data_dir: &Path, request: &Request, wait: Duration) -> NetResult<Response> {
    let mut stream = platform::connect(data_dir)
        .map_err(|_| NetError::Node("no mesh node is running for this data directory"))?;
    let _ = stream.set_read_timeout(Some(wait));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut line = serde_json::to_string(request)
        .map_err(|_| NetError::Node("the control request cannot be encoded"))?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| NetError::Node("the control request could not be sent"))?;
    let mut response = String::new();
    BufReader::new(stream)
        .take(1 << 20)
        .read_line(&mut response)
        .map_err(|_| NetError::Node("the node did not answer in time"))?;
    serde_json::from_str(response.trim())
        .map_err(|_| NetError::Node("the node's answer is not readable"))
}

/// Send a nonce-carrying request built by `build`.
pub fn request(
    data_dir: &Path,
    build: impl FnOnce(String) -> Request,
    wait: Duration,
) -> NetResult<Response> {
    let nonce = read_nonce(data_dir).ok_or(NetError::Node(
        "no mesh node is running for this data directory",
    ))?;
    send(data_dir, &build(nonce.to_string()), wait)
}

/// The pid of the node running for `data_dir`, if one answers.
pub fn running_pid(data_dir: &Path) -> Option<u32> {
    match send(data_dir, &Request::Health, IO_TIMEOUT) {
        Ok(Response::Health { pid }) => Some(pid),
        _ => None,
    }
}

/// The running node's status, if one answers.
pub fn status(data_dir: &Path) -> Option<NodeStatus> {
    match request(data_dir, |nonce| Request::Status { nonce }, IO_TIMEOUT) {
        Ok(Response::Status(s)) => Some(s),
        _ => None,
    }
}

/// Ask the running node to stop. Returns whether it acknowledged.
pub fn stop(data_dir: &Path) -> NetResult<bool> {
    Ok(matches!(
        request(data_dir, |nonce| Request::Stop { nonce }, IO_TIMEOUT)?,
        Response::Ok
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Target {
        stopped: AtomicBool,
        replicated: Mutex<Vec<(Option<String>, bool)>>,
    }

    impl ControlTarget for Target {
        fn status(&self) -> NodeStatus {
            NodeStatus {
                pid: 1,
                device_id: DeviceId::from_bytes([7; 16]),
                started_at: "2026-10-28T00:00:00Z".into(),
                listen: vec!["127.0.0.1:1".into()],
                advertised: vec![],
                interval_ms: 30_000,
                discovery: false,
                rounds: 3,
                last_round_at: None,
                active_sessions: 0,
                hooks: vec![],
                last_hook_error: None,
                last_publish_error: None,
                stopping: false,
            }
        }
        fn replicate_now(&self, peer: Option<String>, repair: bool) -> Response {
            self.replicated.lock().unwrap().push((peer, repair));
            Response::Replicated {
                exchanges: vec![],
                repairs_changed: 0,
            }
        }
        fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }
    }

    fn target() -> Target {
        Target {
            stopped: AtomicBool::new(false),
            replicated: Mutex::new(vec![]),
        }
    }

    #[test]
    fn every_operation_but_health_needs_the_nonce() {
        let t = target();
        let n = "a".repeat(32);
        for wrong in ["", "b", &"b".repeat(32), &format!("{n}x")] {
            let w = wrong.to_owned();
            for req in [
                Request::Status { nonce: w.clone() },
                Request::ReplicateNow {
                    nonce: w.clone(),
                    peer: None,
                    repair: false,
                },
                Request::Stop { nonce: w.clone() },
            ] {
                assert!(matches!(
                    dispatch(&t, &n, req),
                    Response::Error { code, .. } if code == "unauthorized"
                ));
            }
        }
        assert!(!t.stopped.load(Ordering::SeqCst));
        assert!(t.replicated.lock().unwrap().is_empty());
        assert!(matches!(
            dispatch(&t, &n, Request::Health),
            Response::Health { .. }
        ));
        assert!(matches!(
            dispatch(&t, &n, Request::Status { nonce: n.clone() }),
            Response::Status(s) if s.rounds == 3
        ));
        dispatch(
            &t,
            &n,
            Request::ReplicateNow {
                nonce: n.clone(),
                peer: Some("127.0.0.1:9".into()),
                repair: true,
            },
        );
        assert_eq!(
            t.replicated.lock().unwrap().as_slice(),
            &[(Some("127.0.0.1:9".to_owned()), true)]
        );
        assert!(matches!(
            dispatch(&t, &n, Request::Stop { nonce: n.clone() }),
            Response::Ok
        ));
        assert!(t.stopped.load(Ordering::SeqCst));
    }

    #[test]
    fn requests_parse_from_one_json_line_and_never_print_their_nonce() {
        let r: Request =
            serde_json::from_str(r#"{"op":"replicate_now","nonce":"secret-nonce-1"}"#).unwrap();
        assert!(matches!(
            r,
            Request::ReplicateNow {
                peer: None,
                repair: false,
                ..
            }
        ));
        assert!(!format!("{r:?}").contains("secret-nonce-1"));
    }

    #[test]
    fn an_unparseable_or_oversize_request_gets_an_error_not_a_panic() {
        struct Pipe(std::io::Cursor<Vec<u8>>, Vec<u8>);
        impl Read for Pipe {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(b)
            }
        }
        impl Write for Pipe {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.1.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for input in [b"not json\n".to_vec(), vec![b'{'; MAX_REQUEST * 2]] {
            let mut p = Pipe(std::io::Cursor::new(input), Vec::new());
            serve_stream(&mut p, &target(), "n").unwrap();
            let out = String::from_utf8(p.1).unwrap();
            assert!(out.contains("invalid_input"), "{out}");
        }
    }

    #[test]
    fn a_second_claim_on_one_data_directory_is_refused_until_the_first_stops() {
        let dir = tempfile::tempdir().unwrap();
        let first = claim(dir.path()).unwrap();
        let mut server = ControlServer::start(first, Arc::new(target())).unwrap();
        let err = claim(dir.path()).unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");
        assert_eq!(running_pid(dir.path()), Some(std::process::id()));
        assert_eq!(status(dir.path()).unwrap().rounds, 3);
        server.stop();
        assert!(running_pid(dir.path()).is_none());
        assert!(read_nonce(dir.path()).is_none());
        // Nothing is left that blocks the next node.
        drop(claim(dir.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn the_socket_and_nonce_are_owner_only_and_a_stale_socket_is_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let c = claim(dir.path()).unwrap();
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let mesh = marker::mesh_dir(dir.path());
        assert_eq!(mode(mesh.join(SOCKET_NAME)), 0o600);
        assert_eq!(mode(mesh.join(NONCE_NAME)), 0o600);
        assert_eq!(mode(mesh.clone()), 0o700);
        // A claim dropped without serving leaves a socket nobody listens on.
        drop(c);
        assert!(mesh.join(SOCKET_NAME).exists());
        drop(claim(dir.path()).unwrap());
    }
}
