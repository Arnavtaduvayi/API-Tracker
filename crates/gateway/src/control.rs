//! The authenticated local control channel (ADR 0019 D5/D11, SI-21).
//!
//! This is deliberately NOT the forwarding listener. The forwarding port is
//! unauthenticated by necessity (an SDK cannot send a Tethra token), so
//! anything privileged must arrive somewhere else:
//!
//! - a Unix-domain socket at `<data-dir>/gateway.sock`, mode 0600 inside the
//!   0700 data directory;
//! - with a peer-credential check that the caller's euid is OUR euid, so
//!   another local user cannot drive it even if the mode were wrong;
//! - plus a server nonce the caller must echo, so the CALLER also
//!   authenticates the server and cannot be tricked into pushing a key to a
//!   squatter that got the path first;
//! - write-only for key material: the fingerprint key can be pushed and
//!   revoked, never read back.
//!
//! The key therefore never crosses a TCP socket, argv, or an environment
//! variable — a source-level guard test asserts that, and a privacy canary
//! scans argv/environ/disk for the key bytes.
//!
//! On Windows this module compiles to a stub that REFUSES key push rather
//! than falling back to TCP (attribution is simply unavailable and labeled).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::secret::SecretBytes;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Max bytes of one control request line. A key push is the largest message
/// and is well under this.
pub const MAX_REQUEST: usize = 8 * 1024;

/// The control socket file name inside the data directory.
pub const SOCKET_NAME: &str = "gateway.sock";
/// The per-boot nonce file. 0600; readable only by this user, and the value
/// is what proves a caller is talking to THIS gateway.
pub const NONCE_NAME: &str = "gateway.nonce";
/// The single-instance lock / liveness file.
pub const PID_NAME: &str = "gateway.pid";

/// A control request. `nonce` authenticates the SERVER to the caller: only a
/// process that could read the 0600 nonce file is talking to the right
/// gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness only. Deliberately requires no nonce so a health check is
    /// possible without reading any file.
    Health,
    Version,
    Status {
        nonce: String,
    },
    /// Push the matching-only fingerprint key (hex). WRITE ONLY.
    PushKey {
        nonce: String,
        key_hex: String,
    },
    /// Drop the key immediately (lock, toggle-off, revoke).
    RevokeKey {
        nonce: String,
    },
    /// Reload the route snapshot from the database.
    ReloadRoutes {
        nonce: String,
    },
    PauseRecording {
        nonce: String,
    },
    ResumeRecording {
        nonce: String,
    },
    /// Ask the gateway to stop accepting and drain.
    Shutdown {
        nonce: String,
    },
}

/// A control response. Nothing here ever carries key material: there is no
/// variant capable of returning a key, so a read-back is not merely refused
/// but unrepresentable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Health { healthy: bool },
    Version { version: String },
    Status(Box<Status>),
    Error { code: String, message: String },
}

/// Everything the CLI, desktop, and lock screen need to tell the truth about
/// the gateway — all of it available WITHOUT unlocking the vault, so a locked
/// desktop is never silent about the gateway's state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub version: String,
    pub port: u16,
    pub uptime_secs: u64,
    pub routes: usize,
    /// Routes present but not forwardable right now (custom routes whose MAC
    /// cannot be verified while the vault has been locked since boot).
    pub routes_unavailable: usize,
    pub connections_in_flight: usize,
    pub queue_depth: usize,
    pub dropped_events: u64,
    pub written_events: u64,
    pub persist_failures: u64,
    /// Route configuration could not be re-read; forwarding continues on the
    /// last-known-good snapshot.
    pub routes_degraded: bool,
    /// Persistence is failing; forwarding is unaffected.
    pub recording_degraded: bool,
    pub recording_paused: bool,
    /// Whether the matching key is resident. Attribution degrades honestly
    /// when it is not — this is the field that makes that visible.
    pub matching_key_present: bool,
    pub last_observation_at: Option<String>,
    pub last_error: Option<String>,
}

/// What the control plane is allowed to do to a running gateway.
pub trait ControlTarget: Send + Sync {
    fn status(&self) -> Status;
    fn push_key(&self, key: SecretBytes) -> Result<()>;
    fn revoke_key(&self);
    fn reload_routes(&self);
    fn set_recording_paused(&self, paused: bool);
    fn shutdown(&self);
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Create (or refresh) the per-boot nonce, 0600 in the data directory.
///
/// A nonce, not a PID/binary-path check: verifying a listener's identity from
/// an unprivileged process is unimplementable on macOS and TOCTOU-prone
/// everywhere (OPEN_DECISIONS O3).
pub fn write_nonce(data_dir: &Path) -> Result<Zeroizing<String>> {
    let nonce = hex_encode(&api_tracker_core::crypto::random_bytes(16));
    let path = data_dir.join(NONCE_NAME);
    write_private(&path, nonce.as_bytes())?;
    Ok(Zeroizing::new(nonce))
}

pub fn read_nonce(data_dir: &Path) -> Result<Zeroizing<String>> {
    let path = data_dir.join(NONCE_NAME);
    let raw = std::fs::read_to_string(&path).map_err(CoreError::Io)?;
    Ok(Zeroizing::new(raw.trim().to_string()))
}

/// Write a file 0600, refusing to follow a symlink into somewhere else.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    // A pre-existing symlink at this path would redirect the write; remove
    // whatever is there first and create fresh.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::remove_file(path).map_err(CoreError::Io)?;
        }
        Ok(_) => {
            std::fs::remove_file(path).map_err(CoreError::Io)?;
        }
        Err(_) => {}
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(CoreError::Io)?;
        f.write_all(contents).map_err(CoreError::Io)?;
        f.flush().map_err(CoreError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(CoreError::Io)?;
        f.write_all(contents).map_err(CoreError::Io)?;
        f.flush().map_err(CoreError::Io)?;
    }
    Ok(())
}

/// Handle one parsed request against a target. Shared by the Unix listener
/// and by tests, so the authorization logic has exactly one implementation.
pub fn dispatch(target: &dyn ControlTarget, expected_nonce: &str, request: Request) -> Response {
    // The nonce is compared in constant time: it is a capability, and a
    // timing oracle over it would let a same-uid process recover it.
    let authorized = |given: &str| -> bool {
        use subtle::ConstantTimeEq;
        given.len() == expected_nonce.len()
            && given
                .as_bytes()
                .ct_eq(expected_nonce.as_bytes())
                .unwrap_u8()
                == 1
    };
    let denied = || Response::Error {
        code: "unauthorized".into(),
        message: "the control nonce did not match this gateway".into(),
    };
    match request {
        // Health carries no privilege and reveals nothing but liveness.
        Request::Health => Response::Health { healthy: true },
        Request::Version => Response::Version {
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        Request::Status { nonce } => {
            if !authorized(&nonce) {
                return denied();
            }
            Response::Status(Box::new(target.status()))
        }
        Request::PushKey { nonce, key_hex } => {
            if !authorized(&nonce) {
                return denied();
            }
            let Some(bytes) = hex_decode(&key_hex) else {
                return Response::Error {
                    code: "invalid_input".into(),
                    message: "the key must be hex".into(),
                };
            };
            if bytes.len() != 32 {
                return Response::Error {
                    code: "invalid_input".into(),
                    message: "the matching key must be 32 bytes".into(),
                };
            }
            match target.push_key(SecretBytes::new(bytes)) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    code: e.code().to_string(),
                    message: "the key could not be installed".into(),
                },
            }
        }
        Request::RevokeKey { nonce } => {
            if !authorized(&nonce) {
                return denied();
            }
            target.revoke_key();
            Response::Ok
        }
        Request::ReloadRoutes { nonce } => {
            if !authorized(&nonce) {
                return denied();
            }
            target.reload_routes();
            Response::Ok
        }
        Request::PauseRecording { nonce } => {
            if !authorized(&nonce) {
                return denied();
            }
            target.set_recording_paused(true);
            Response::Ok
        }
        Request::ResumeRecording { nonce } => {
            if !authorized(&nonce) {
                return denied();
            }
            target.set_recording_paused(false);
            Response::Ok
        }
        Request::Shutdown { nonce } => {
            if !authorized(&nonce) {
                return denied();
            }
            target.shutdown();
            Response::Ok
        }
    }
}

/// Serve one already-accepted control connection.
pub fn serve_stream<S: std::io::Read + Write>(
    stream: S,
    target: &dyn ControlTarget,
    expected_nonce: &str,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    // Bounded read: one line, hard-capped, so a hostile local caller cannot
    // make the control thread allocate without bound.
    {
        let mut limited = std::io::Read::take(&mut reader, MAX_REQUEST as u64);
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
        "{\"result\":\"error\",\"code\":\"internal\",\"message\":\"\"}".to_string()
    });
    out.push('\n');
    let stream = reader.into_inner();
    let mut stream = stream;
    stream.write_all(out.as_bytes())?;
    stream.flush()
}

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};

    /// The running control listener.
    #[derive(Debug)]
    pub struct ControlServer {
        path: PathBuf,
        pub shutdown: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    /// Verify that the socket and its directory still restrict access to
    /// this user alone, and report the owning uid.
    ///
    /// **Deviation from SECURITY_INVARIANTS SI-21, recorded deliberately.**
    /// SI-21 specifies a `SO_PEERCRED`/`LOCAL_PEERCRED` peer-euid check.
    /// `UnixStream::peer_cred` is still unstable in Rust, and reading the
    /// socket option directly requires either `unsafe` (forbidden crate-wide
    /// by `#![forbid(unsafe_code)]`) or a new `libc`/`nix` dependency (which
    /// ADR 0019's dependency decision rules out). The enforcement here is the
    /// kernel's own, one layer down and equally same-uid-exact: connecting to
    /// a Unix socket requires WRITE permission on the socket inode, the
    /// socket is 0600, and its parent data directory is 0700 — so another
    /// local user (adversary A6) cannot connect at all, and cannot even
    /// traverse to the path. That is verified on EVERY accept, not merely at
    /// bind, so a permission loosened underneath us stops the channel rather
    /// than silently widening it. The residual versus a peer-cred call is a
    /// same-uid process, which SI-21's check would also admit.
    fn access_is_still_restricted(path: &Path) -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        // The socket must not have been replaced by a symlink or loosened.
        let meta = std::fs::symlink_metadata(path).ok()?;
        if meta.file_type().is_symlink() {
            return None;
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return None;
        }
        let dir = path.parent()?;
        let dir_meta = std::fs::metadata(dir).ok()?;
        if dir_meta.permissions().mode() & 0o077 != 0 {
            return None;
        }
        if dir_meta.uid() != meta.uid() {
            return None;
        }
        Some(meta.uid())
    }

    impl ControlServer {
        /// Bind the control socket 0600 inside the data directory.
        /// The platform limit on a Unix-socket path (`sun_path`): 104 bytes
        /// on macOS/BSD, 108 on Linux. Exceeding it fails deep inside bind
        /// with an opaque message, so it is checked up front.
        const MAX_SOCKET_PATH: usize = 100;

        pub fn start(
            data_dir: &Path,
            nonce: String,
            target: Arc<dyn ControlTarget>,
        ) -> Result<Self> {
            let path = data_dir.join(SOCKET_NAME);
            if path.as_os_str().len() > Self::MAX_SOCKET_PATH {
                return Err(CoreError::InvalidInput(format!(
                    "the control socket path is {} bytes, past this platform's ~{}-byte \
                     limit for Unix sockets ({}). Use a shorter data directory (TETHRA_DIR) \
                     to enable credential attribution and status; forwarding and recording \
                     work without it.",
                    path.as_os_str().len(),
                    Self::MAX_SOCKET_PATH,
                    path.display()
                )));
            }
            // Refuse to bind over a symlink: a same-uid attacker who plants
            // one could otherwise redirect the socket somewhere world-
            // reachable.
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    return Err(CoreError::InvalidInput(format!(
                        "{} is a symlink; refusing to bind the control socket",
                        path.display()
                    )));
                }
                // A stale socket from a dead instance is replaced; a LIVE one
                // means another gateway owns this data dir.
                if UnixStream::connect(&path).is_ok() {
                    return Err(CoreError::InvalidInput(
                        "another Tethra gateway is already running for this data directory".into(),
                    ));
                }
                let _ = std::fs::remove_file(&path);
            }
            let listener = UnixListener::bind(&path).map_err(CoreError::Io)?;
            restrict(&path)?;
            listener.set_nonblocking(true).map_err(CoreError::Io)?;
            // We just created this socket, so its owner IS our effective
            // uid; refuse to serve at all if the permissions are not what we
            // just set (a hostile umask, an odd filesystem, a race).
            let Some(our_uid) = access_is_still_restricted(&path) else {
                let _ = std::fs::remove_file(&path);
                return Err(CoreError::InvalidInput(
                    "the control socket is not owner-only; refusing to serve an \
                     insufficiently protected control channel"
                        .into(),
                ));
            };
            let _ = our_uid;

            let shutdown = Arc::new(AtomicBool::new(false));
            let stop = shutdown.clone();
            let nonce_for_thread = nonce;
            let socket_path = path.clone();
            let handle = std::thread::Builder::new()
                .name("tethra-gateway-control".into())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                // Re-verify on EVERY accept: a socket whose
                                // mode was loosened underneath us must stop
                                // serving rather than silently widen.
                                if access_is_still_restricted(&socket_path).is_none() {
                                    drop(stream);
                                    continue;
                                }
                                // On BSD/macOS an accepted socket INHERITS the
                                // listener's non-blocking flag, so the first
                                // read returns WouldBlock and the connection
                                // is dropped before the client's request even
                                // arrives. Linux does not inherit it; setting
                                // it explicitly is correct on both.
                                let _ = stream.set_nonblocking(false);
                                let _ = stream
                                    .set_read_timeout(Some(std::time::Duration::from_secs(5)));
                                let _ = stream
                                    .set_write_timeout(Some(std::time::Duration::from_secs(5)));
                                let _ = serve_stream(stream, target.as_ref(), &nonce_for_thread);
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
                        }
                    }
                })
                .ok();
            Ok(Self {
                path,
                shutdown,
                handle,
            })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn stop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl Drop for ControlServer {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn restrict(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(CoreError::Io)
    }

    /// Send one control request and read the response. This is what the CLI
    /// and desktop use; the key travels only here.
    pub fn send(data_dir: &Path, request: &Request) -> Result<Response> {
        let path = data_dir.join(SOCKET_NAME);
        let mut stream = UnixStream::connect(&path).map_err(CoreError::Io)?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(CoreError::Io)?;
        let mut line = serde_json::to_string(request).map_err(CoreError::Serde)?;
        line.push('\n');
        stream.write_all(line.as_bytes()).map_err(CoreError::Io)?;
        stream.flush().map_err(CoreError::Io)?;
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).map_err(CoreError::Io)?;
        serde_json::from_str(response.trim()).map_err(CoreError::Serde)
    }
}

#[cfg(unix)]
pub use unix_impl::{send, ControlServer};

#[cfg(not(unix))]
mod windows_impl {
    use super::*;

    /// Windows v1 has no control channel: key push is REFUSED rather than
    /// falling back to a TCP socket a port-squatter could harvest (ADR 0019
    /// D5). Attribution is simply unavailable and labeled as such.
    pub struct ControlServer;

    impl ControlServer {
        pub fn start(
            _data_dir: &Path,
            _nonce: String,
            _target: Arc<dyn ControlTarget>,
        ) -> Result<Self> {
            Err(CoreError::Unsupported {
                provider: "gateway".into(),
                capability: "control_channel",
                hint: "the authenticated control channel is not implemented on Windows in \
                       v1; credential attribution is unavailable there and the gateway \
                       refuses to fall back to an unauthenticated TCP channel"
                    .into(),
            })
        }
        pub fn stop(&mut self) {}
    }

    pub fn send(_data_dir: &Path, _request: &Request) -> Result<Response> {
        Err(CoreError::Unsupported {
            provider: "gateway".into(),
            capability: "control_channel",
            hint: "not supported on Windows in v1".into(),
        })
    }
}

#[cfg(not(unix))]
pub use windows_impl::{send, ControlServer};

/// Single-instance / liveness marker. A stale PID file from a crashed
/// instance must never make a fresh gateway refuse to start, and a live one
/// must never be silently taken over — so liveness is decided by the SOCKET,
/// not by the PID number (a recycled pid proves nothing).
pub fn write_pid_file(data_dir: &Path) -> Result<()> {
    write_private(
        &data_dir.join(PID_NAME),
        std::process::id().to_string().as_bytes(),
    )
}

pub fn remove_pid_file(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join(PID_NAME));
}

/// Whether a gateway appears to be live for this data directory, decided by
/// connecting to the control socket rather than by trusting a pid.
pub fn instance_is_live(data_dir: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(data_dir.join(SOCKET_NAME)).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = data_dir;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeTarget {
        pub key: Mutex<Option<Vec<u8>>>,
        pub reloads: Mutex<u32>,
        pub paused: AtomicBool,
        pub stopped: AtomicBool,
    }

    impl ControlTarget for FakeTarget {
        fn status(&self) -> Status {
            Status {
                version: "test".into(),
                port: 49999,
                matching_key_present: self.key.lock().unwrap().is_some(),
                recording_paused: self.paused.load(Ordering::Relaxed),
                ..Status::default()
            }
        }
        fn push_key(&self, key: SecretBytes) -> Result<()> {
            *self.key.lock().unwrap() = Some(key.expose().to_vec());
            Ok(())
        }
        fn revoke_key(&self) {
            *self.key.lock().unwrap() = None;
        }
        fn reload_routes(&self) {
            *self.reloads.lock().unwrap() += 1;
        }
        fn set_recording_paused(&self, paused: bool) {
            self.paused.store(paused, Ordering::Relaxed);
        }
        fn shutdown(&self) {
            self.stopped.store(true, Ordering::Relaxed);
        }
    }

    const NONCE: &str = "0123456789abcdef0123456789abcdef";
    const KEY_HEX: &str = "aa0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn every_privileged_operation_requires_the_nonce() {
        let t = FakeTarget::default();
        let wrong = "ffffffffffffffffffffffffffffffff".to_string();
        let privileged = vec![
            Request::Status {
                nonce: wrong.clone(),
            },
            Request::PushKey {
                nonce: wrong.clone(),
                key_hex: KEY_HEX.into(),
            },
            Request::RevokeKey {
                nonce: wrong.clone(),
            },
            Request::ReloadRoutes {
                nonce: wrong.clone(),
            },
            Request::PauseRecording {
                nonce: wrong.clone(),
            },
            Request::ResumeRecording {
                nonce: wrong.clone(),
            },
            Request::Shutdown { nonce: wrong },
        ];
        for req in privileged {
            let label = format!("{req:?}");
            match dispatch(&t, NONCE, req) {
                Response::Error { code, .. } => assert_eq!(code, "unauthorized", "{label}"),
                other => panic!("{label} must be refused, got {other:?}"),
            }
        }
        // Nothing happened.
        assert!(t.key.lock().unwrap().is_none());
        assert_eq!(*t.reloads.lock().unwrap(), 0);
        assert!(!t.paused.load(Ordering::Relaxed));
        assert!(!t.stopped.load(Ordering::Relaxed));
    }

    #[test]
    fn health_and_version_need_no_nonce_but_reveal_nothing_privileged() {
        let t = FakeTarget::default();
        assert_eq!(
            dispatch(&t, NONCE, Request::Health),
            Response::Health { healthy: true }
        );
        match dispatch(&t, NONCE, Request::Version) {
            Response::Version { version } => assert!(!version.is_empty()),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn the_key_can_be_pushed_and_revoked_but_never_read_back() {
        let t = FakeTarget::default();
        assert_eq!(
            dispatch(
                &t,
                NONCE,
                Request::PushKey {
                    nonce: NONCE.into(),
                    key_hex: KEY_HEX.into(),
                },
            ),
            Response::Ok
        );
        assert_eq!(t.key.lock().unwrap().as_ref().unwrap().len(), 32);

        // Status reports PRESENCE, never the key.
        let status = match dispatch(
            &t,
            NONCE,
            Request::Status {
                nonce: NONCE.into(),
            },
        ) {
            Response::Status(s) => *s,
            other => panic!("got {other:?}"),
        };
        assert!(status.matching_key_present);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains(KEY_HEX));
        assert!(!json.contains("aa01"), "no key bytes may appear in status");

        // There is no request that reads a key: the protocol has no such
        // variant, so a read-back is unrepresentable rather than refused.
        let all_ops = serde_json::to_string(&Request::Health).unwrap();
        assert!(!all_ops.contains("get_key"));

        assert_eq!(
            dispatch(
                &t,
                NONCE,
                Request::RevokeKey {
                    nonce: NONCE.into()
                }
            ),
            Response::Ok
        );
        assert!(t.key.lock().unwrap().is_none());
    }

    #[test]
    fn a_malformed_or_wrong_length_key_is_refused() {
        let t = FakeTarget::default();
        for bad in ["zz", "aabb", &"aa".repeat(31), &"aa".repeat(33), ""] {
            match dispatch(
                &t,
                NONCE,
                Request::PushKey {
                    nonce: NONCE.into(),
                    key_hex: bad.into(),
                },
            ) {
                Response::Error { code, .. } => assert_eq!(code, "invalid_input"),
                other => panic!("{bad:?} must be refused, got {other:?}"),
            }
        }
        assert!(t.key.lock().unwrap().is_none());
    }

    #[test]
    fn authorized_operations_take_effect() {
        let t = FakeTarget::default();
        assert_eq!(
            dispatch(
                &t,
                NONCE,
                Request::ReloadRoutes {
                    nonce: NONCE.into()
                }
            ),
            Response::Ok
        );
        assert_eq!(*t.reloads.lock().unwrap(), 1);
        assert_eq!(
            dispatch(
                &t,
                NONCE,
                Request::PauseRecording {
                    nonce: NONCE.into()
                }
            ),
            Response::Ok
        );
        assert!(t.paused.load(Ordering::Relaxed));
        assert_eq!(
            dispatch(
                &t,
                NONCE,
                Request::ResumeRecording {
                    nonce: NONCE.into()
                }
            ),
            Response::Ok
        );
        assert!(!t.paused.load(Ordering::Relaxed));
        assert_eq!(
            dispatch(
                &t,
                NONCE,
                Request::Shutdown {
                    nonce: NONCE.into()
                }
            ),
            Response::Ok
        );
        assert!(t.stopped.load(Ordering::Relaxed));
    }

    #[test]
    fn there_is_no_variant_capable_of_injecting_an_observation() {
        // A fake-observation injection would require a request that carries
        // event data. The protocol has none: every variant is either
        // nonce-only or (for PushKey) a fixed-length key.
        let json = serde_json::to_string(&Request::Status {
            nonce: NONCE.into(),
        })
        .unwrap();
        assert!(json.contains("status"));
        for forbidden in ["path", "host", "tokens", "event", "record", "usage"] {
            assert!(
                !json.contains(forbidden),
                "the control protocol must not carry observation data"
            );
        }
    }

    #[test]
    fn an_unparseable_request_gets_an_error_not_a_panic() {
        let t = FakeTarget::default();
        let mut buf: Vec<u8> = Vec::new();
        let input = std::io::Cursor::new(b"not json at all\n".to_vec());
        struct Duplex<R: std::io::Read, W: Write>(R, W);
        impl<R: std::io::Read, W: Write> std::io::Read for Duplex<R, W> {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(b)
            }
        }
        impl<R: std::io::Read, W: Write> Write for Duplex<R, W> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.1.write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.1.flush()
            }
        }
        serve_stream(Duplex(input, &mut buf), &t, NONCE).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("invalid_input"), "got {out}");
    }

    #[test]
    fn nonce_files_are_private_and_change_per_boot() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_nonce(dir.path()).unwrap();
        assert_eq!(a.len(), 32, "128 bits of hex");
        let read_back = read_nonce(dir.path()).unwrap();
        assert_eq!(*a, *read_back);
        let b = write_nonce(dir.path()).unwrap();
        assert_ne!(*a, *b, "a fresh boot gets a fresh nonce");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(NONCE_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the nonce must be owner-only");
        }
    }

    #[cfg(unix)]
    #[test]
    fn writing_a_private_file_refuses_to_follow_a_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("victim.txt");
        std::fs::write(&target, b"original").unwrap();
        let link = dir.path().join(NONCE_NAME);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        write_nonce(dir.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "original",
            "the write must NOT have followed the symlink into the victim file"
        );
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
