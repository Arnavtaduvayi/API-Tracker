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
