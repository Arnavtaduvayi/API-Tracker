//! The only function in this crate that binds a socket (MESH-SI-1).
//!
//! A mesh listener binds exactly the address it is given. An unspecified
//! address (`0.0.0.0` or `::`, "every interface") is refused unless the
//! caller passes `allow_all_interfaces`, which only the `--all-interfaces`
//! flag sets. Nothing in this crate listens unless `serve` was given
//! `--listen`. `tests/bind_guard.rs` fails the build if any other file binds.

use std::io;
use std::net::{SocketAddr, TcpListener};

/// Bind a TCP listener on `addr`, refusing unspecified addresses unless
/// `allow_all_interfaces`.
pub fn bind_listener(addr: SocketAddr, allow_all_interfaces: bool) -> io::Result<TcpListener> {
    if addr.ip().is_unspecified() && !allow_all_interfaces {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to listen on every interface; pass --all-interfaces to allow it",
        ));
    }
    TcpListener::bind(addr)
}

/// Bind the node's local control socket (Unix): the single-instance lock
/// and the channel `status`, `replicate-now` and `stop` arrive on
/// ([`crate::instance`]). The caller checked that nothing live owns `path`
/// and restricts it to this user right after.
#[cfg(unix)]
pub fn bind_control_socket(path: &std::path::Path) -> io::Result<std::os::unix::net::UnixListener> {
    std::os::unix::net::UnixListener::bind(path)
}

/// Windows has no Unix socket here: the control channel is a loopback TCP
/// listener on an ephemeral port, written to the nonce file.
#[cfg(not(unix))]
pub fn bind_control_loopback() -> io::Result<TcpListener> {
    bind_listener(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)), false)
}
