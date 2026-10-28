//! Errors of the network layer. Every message is static text or an
//! identifier: never key material, a token, an invite string or bytes a peer
//! sent.

use api_tracker_core::mesh::MeshError;
use api_tracker_core::CoreError;
use std::fmt;

#[derive(Debug)]
pub enum NetError {
    /// The connection failed or timed out (the I/O error kind only).
    Io(std::io::ErrorKind),
    /// The Noise handshake failed: a wrong key, a wrong mesh, a malformed
    /// message, or a peer that gave up.
    Handshake(&'static str),
    /// The peer authenticated but is not allowed here (not an active member).
    Refused(&'static str),
    /// The replication session ended early.
    Session(&'static str),
    Core(CoreError),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Io(k) => write!(f, "mesh connection failed ({k})"),
            NetError::Handshake(why) => write!(f, "mesh handshake failed: {why}"),
            NetError::Refused(why) => write!(f, "mesh connection refused: {why}"),
            NetError::Session(why) => write!(f, "mesh exchange ended early: {why}"),
            NetError::Core(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for NetError {}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(e.kind())
    }
}

impl From<CoreError> for NetError {
    fn from(e: CoreError) -> Self {
        NetError::Core(e)
    }
}

impl From<MeshError> for NetError {
    fn from(e: MeshError) -> Self {
        NetError::Core(CoreError::Mesh(e))
    }
}

impl NetError {
    /// A static description for `mesh_exchange_log.error`.
    pub fn log_text(&self) -> &'static str {
        match self {
            NetError::Io(_) => "connection failed",
            NetError::Handshake(w) | NetError::Refused(w) | NetError::Session(w) => w,
            NetError::Core(_) => "local error",
        }
    }
}

pub type NetResult<T> = Result<T, NetError>;
