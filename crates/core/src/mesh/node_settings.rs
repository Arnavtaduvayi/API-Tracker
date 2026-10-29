//! How the desktop app runs this device's mesh node (Increment 09, DESIGN
//! §D13): local-only settings in `mesh_meta` (`node/settings`), never
//! replicated, wiped with the rest of the mesh rows by `leave` and restore.
//!
//! The settings mirror `tethra mesh serve`'s flags. Nothing listens by
//! default (MESH-SI-1): `listen` starts empty and the node needs at least one
//! address. **Widening who on the network can reach this device** needs the
//! master password, enforced here and not in the UI ([`needs_reauth`]):
//! - turning on `all_interfaces` (it permits `0.0.0.0` / `[::]` in `listen`);
//! - turning on `discover` (mDNS announcements on the LAN);
//! - adding a listen address that is not a loopback address.
//!
//! Narrowing (turning either off, removing addresses, loopback addresses) does
//! not.

use super::kinds::MAX_LISTEN_ADDRS;
use super::MeshError;
use crate::error::Result;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// The `mesh_meta` key that holds the settings (JSON).
pub const KEY: &str = "node/settings";

/// How this device's in-process node runs (the desktop's "Run mesh while
/// Tethra is open").
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSettings {
    /// Start the node after every unlock and keep it running while the app
    /// is open and unlocked.
    pub run_while_open: bool,
    /// `IP:PORT` addresses to listen on, normalized (`SocketAddr` display
    /// form). Port 0 picks a free port at each start.
    pub listen: Vec<String>,
    /// Allow `0.0.0.0` / `[::]` in `listen` (`--all-interfaces`).
    pub all_interfaces: bool,
    /// Announce and find devices of this mesh with mDNS (`--discover`).
    pub discover: bool,
}

impl NodeSettings {
    /// The listen addresses, parsed. [`validate`] guarantees they parse.
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.listen.iter().filter_map(|a| a.parse().ok()).collect()
    }
}

fn invalid(why: &'static str) -> crate::error::CoreError {
    MeshError::InvalidNodeSettings(why).into()
}

/// Check and normalize `s`: every listen address an `IP:PORT` literal
/// (trimmed, de-duplicated, at most [`MAX_LISTEN_ADDRS`]), an unspecified
/// address only with `all_interfaces`, and at least one address when the
/// node is to run.
pub fn validate(s: &NodeSettings) -> Result<NodeSettings> {
    let mut listen: Vec<String> = Vec::new();
    for raw in &s.listen {
        let addr: SocketAddr = raw
            .trim()
            .parse()
            .map_err(|_| invalid("a listen address must be IP:PORT, such as 127.0.0.1:7700"))?;
        if addr.ip().is_unspecified() && !s.all_interfaces {
            return Err(invalid(
                "listening on every interface (0.0.0.0 or [::]) needs \"all interfaces\" turned on",
            ));
        }
        let text = addr.to_string();
        if !listen.contains(&text) {
            listen.push(text);
        }
    }
    if listen.len() > MAX_LISTEN_ADDRS {
        return Err(invalid("at most 16 listen addresses"));
    }
    if s.run_while_open && listen.is_empty() {
        return Err(invalid(
            "the node needs a listen address before it can run; add one such as 127.0.0.1:7700",
        ));
    }
    Ok(NodeSettings {
        run_while_open: s.run_while_open,
        listen,
        all_interfaces: s.all_interfaces,
        discover: s.discover,
    })
}

/// How going from `old` to `new` widens this device's LAN surface (module
/// docs), as static descriptions; empty when it does not. Both must be
/// normalized.
pub fn widenings(old: &NodeSettings, new: &NodeSettings) -> Vec<&'static str> {
    let mut out = Vec::new();
    if new.all_interfaces && !old.all_interfaces {
        out.push("all interfaces allowed");
    }
    if new.discover && !old.discover {
        out.push("mDNS discovery on");
    }
    if new.listen.iter().any(|a| {
        !old.listen.contains(a)
            && a.parse::<SocketAddr>()
                .map_or(true, |s| !s.ip().is_loopback())
    }) {
        out.push("a non-loopback listen address added");
    }
    out
}

/// Whether going from `old` to `new` needs the master password.
pub fn needs_reauth(old: &NodeSettings, new: &NodeSettings) -> bool {
    !widenings(old, new).is_empty()
}

/// The stored settings, or the defaults (nothing runs, nothing listens).
/// A row that no longer parses reads as the defaults: the safe reading.
pub fn get(conn: &Connection) -> Result<NodeSettings> {
    let raw: Option<String> = conn
        .query_row("SELECT value FROM mesh_meta WHERE key = ?1", [KEY], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(raw
        .and_then(|v| serde_json::from_str::<NodeSettings>(&v).ok())
        .and_then(|s| validate(&s).ok())
        .unwrap_or_default())
}

/// Store already-validated settings.
pub fn put(conn: &Connection, s: &NodeSettings) -> Result<()> {
    let json = serde_json::to_string(s).map_err(|_| invalid("the settings cannot be stored"))?;
    conn.execute(
        "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES (?1, ?2)",
        rusqlite::params![KEY, json],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(listen: &[&str], all: bool, discover: bool) -> NodeSettings {
        NodeSettings {
            run_while_open: false,
            listen: listen.iter().map(|a| (*a).to_owned()).collect(),
            all_interfaces: all,
            discover,
        }
    }

    #[test]
    fn validation_normalizes_and_refuses_what_the_node_would_refuse() {
        let v = validate(&s(
            &[" 127.0.0.1:7700 ", "127.0.0.1:7700", "[::1]:0"],
            false,
            false,
        ))
        .unwrap();
        assert_eq!(v.listen, vec!["127.0.0.1:7700", "[::1]:0"]);
        assert!(validate(&s(&["localhost:7700"], false, false)).is_err());
        assert!(validate(&s(&["127.0.0.1"], false, false)).is_err());
        assert!(validate(&s(&["0.0.0.0:7700"], false, false)).is_err());
        assert!(validate(&s(&["[::]:7700"], false, false)).is_err());
        assert!(validate(&s(&["0.0.0.0:7700"], true, false)).is_ok());
        let mut run = s(&[], false, false);
        run.run_while_open = true;
        assert!(validate(&run).is_err(), "a running node needs an address");
        let many: Vec<String> = (0..17).map(|i| format!("127.0.0.1:{}", 7000 + i)).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(validate(&s(&refs, false, false)).is_err());
    }

    #[test]
    fn only_widening_the_lan_surface_needs_the_password() {
        let base = s(&["127.0.0.1:7700"], false, false);
        assert!(!needs_reauth(&base, &base));
        assert!(!needs_reauth(&base, &s(&[], false, false)));
        assert!(!needs_reauth(
            &base,
            &s(&["127.0.0.1:7701", "[::1]:7700"], false, false)
        ));
        assert!(needs_reauth(&base, &s(&["127.0.0.1:7700"], true, false)));
        assert!(needs_reauth(&base, &s(&["127.0.0.1:7700"], false, true)));
        assert!(needs_reauth(
            &base,
            &s(&["192.168.1.20:7700"], false, false)
        ));
        assert!(needs_reauth(&base, &s(&["100.64.1.2:7700"], false, false)));
        // Already allowed: keeping it, or turning things off, is free.
        let wide = s(&["192.168.1.20:7700"], true, true);
        assert!(!needs_reauth(&wide, &wide));
        assert!(!needs_reauth(
            &wide,
            &s(&["192.168.1.20:7700"], false, false)
        ));
    }
}
