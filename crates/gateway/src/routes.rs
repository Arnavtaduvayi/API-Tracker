//! The secure route table (ADR 0019 D3).
//!
//! Trust model: the first path segment selects a route, and the route's
//! upstream origin comes from exactly one of two places — the compiled-in
//! provider manifest (install tree), or a user-consented custom origin whose
//! row carries a MAC under a vault-derived key. The plaintext, same-uid-
//! writable `gateway_routes` table is NEVER the trust root: a bare `UPDATE`
//! cannot redirect a live pass-through credential (the Phase 1 adversarial
//! review's route-row-tampering blocker). Origins are additionally re-checked
//! against the observe SSRF policy at load AND resolved-address-checked at
//! connect time (two-phase, `crate::forward`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::secret::SecretBytes;
use api_tracker_core::{audit, clock, crypto, db, providers};
use api_tracker_observe::policy;
use rusqlite::{params, Connection, OptionalExtension};

/// Reserved first path segments that can never be route prefixes: `p` starts
/// the link-scoped form `/p/<slug>/<route>`, and the `_tethra` namespace is
/// the listener's reserved probe path (nonce echo, D11).
pub const RESERVED_PREFIXES: &[&str] = &["p", "_tethra"];

/// Max length of a route prefix (generous; prefixes are human-chosen labels).
pub const MAX_PREFIX_LEN: usize = 32;

/// Validate a candidate route prefix: lowercase alphanumeric/hyphen, starts
/// with a letter, bounded, and not a reserved segment.
pub fn validate_route_prefix(prefix: &str) -> Result<()> {
    let err = |msg: String| Err(CoreError::InvalidInput(msg));
    if prefix.is_empty() || prefix.len() > MAX_PREFIX_LEN {
        return err(format!(
            "route prefix must be 1..={MAX_PREFIX_LEN} characters"
        ));
    }
    if !prefix
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase())
    {
        return err("route prefix must start with a lowercase letter".into());
    }
    if !prefix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return err(format!(
            "route prefix '{prefix}' may only contain lowercase letters, digits, and '-'"
        ));
    }
    if RESERVED_PREFIXES.contains(&prefix) {
        return err(format!("route prefix '{prefix}' is reserved"));
    }
    Ok(())
}

/// Validate a route origin string the way ADR 0019 D3 requires: https-only,
/// bare authority (no path/query/fragment/userinfo), port 443 only, and the
/// observe SSRF policy (loopback, RFC1918, link-local, CGNAT, cloud-metadata
/// names all denied). Returns the (lowercased host, 443) pair.
pub fn validate_origin(origin: &str) -> Result<(String, u16)> {
    let err = |msg: String| Err(CoreError::InvalidInput(msg));
    let Some(rest) = origin.strip_prefix("https://") else {
        return err(format!("origin '{origin}' must be https"));
    };
    if rest.contains(['/', '?', '#']) {
        return err(format!(
            "origin '{origin}' must be a bare authority (no path, query, or fragment)"
        ));
    }
    if rest.contains('@') {
        return err(format!("origin '{origin}' must not carry userinfo"));
    }
    let (host, port) = if rest.starts_with('[') {
        match rest.split_once("]:") {
            Some((h, p)) => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| CoreError::InvalidInput(format!("origin '{origin}': bad port")))?;
                (format!("{h}]"), port)
            }
            None => (rest.to_string(), 443),
        }
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| CoreError::InvalidInput(format!("origin '{origin}': bad port")))?;
                (h.to_string(), port)
            }
            None => (rest.to_string(), 443),
        }
    };
    if port != 443 {
        return err(format!("origin '{origin}' must use port 443"));
    }
    if host.is_empty() {
        return err("origin has an empty host".into());
    }
    let host = host.to_lowercase();
    let verdict = policy::check_authority(&host, port, &policy::AllowList::new());
    if !verdict.is_allowed() {
        return err(format!(
            "origin '{origin}' is denied by the destination policy (loopback, private, \
             link-local, and cloud-metadata targets are never routable)"
        ));
    }
    Ok((host, port))
}

/// Compute the custom-origin route MAC: a BLAKE3 keyed hash over the
/// length-prefixed identity fields, so no field boundary is ambiguous.
/// Binding the vault id, provider id, origin, port, and consent timestamp
/// means changing ANY of them in the DB invalidates the MAC.
pub fn route_mac(
    mac_key: &SecretBytes,
    vault_id: &str,
    provider_id: &str,
    origin_host: &str,
    port: u16,
    consent_ts: &str,
) -> Result<[u8; 32]> {
    let key: &[u8; 32] = mac_key.expose().try_into().map_err(|_| CoreError::Crypto {
        context: "gateway MAC key length",
    })?;
    let mut message = Vec::with_capacity(96);
    message.extend_from_slice(b"tethra:gateway-route-mac:v1");
    for field in [vault_id, provider_id, origin_host, consent_ts] {
        message.extend_from_slice(&(field.len() as u64).to_le_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    message.extend_from_slice(&port.to_le_bytes());
    Ok(*blake3::keyed_hash(key, &message).as_bytes())
}

fn vault_id_of(conn: &Connection) -> Result<String> {
    conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'vault_id'",
        [],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(CoreError::VaultCorrupted("vault_meta has no vault_id"))
}

/// Register a manifest-backed route. The provider must declare a `[gateway]`
/// section — that compiled-in declaration, not this row, is what the route
/// will forward to.
pub fn add_manifest_route(conn: &Connection, prefix: &str, provider: &str) -> Result<()> {
    validate_route_prefix(prefix)?;
    let provider_id = providers::normalize(provider);
    let manifest = providers::find(&provider_id).ok_or_else(|| CoreError::NotFound {
        kind: "provider",
        ident: provider_id.clone(),
    })?;
    let Some(gateway) = &manifest.gateway else {
        return Err(CoreError::Unsupported {
            provider: provider_id,
            capability: "gateway_route",
            hint: "this provider has no fixed data-plane origin; register a custom origin instead"
                .into(),
        });
    };
    // Belt and braces: the compiled-in origin must itself pass validation.
    for origin in &gateway.origins {
        validate_origin(origin)?;
    }
    insert_route(conn, prefix, &provider_id, None)?;
    audit::record(
        conn,
        "gateway_route_added",
        None,
        None,
        &format!("prefix={prefix} provider={provider_id}"),
    )?;
    Ok(())
}

/// Register a custom-origin route (Supabase-style per-project origins,
/// KNOWN_CONFLICTS C11). Requires the vault-derived MAC key — i.e. an
/// unlocked vault at consent time, by construction.
pub fn add_custom_route(
    conn: &Connection,
    prefix: &str,
    provider: &str,
    origin: &str,
    mac_key: &SecretBytes,
) -> Result<()> {
    validate_route_prefix(prefix)?;
    let provider_id = providers::normalize(provider);
    if providers::find(&provider_id).is_none() {
        return Err(CoreError::NotFound {
            kind: "provider",
            ident: provider_id,
        });
    }
    let (host, port) = validate_origin(origin)?;
    let vault_id = vault_id_of(conn)?;
    let consent_ts = clock::now_rfc3339();
    let mac = route_mac(mac_key, &vault_id, &provider_id, &host, port, &consent_ts)?;
    insert_route(
        conn,
        prefix,
        &provider_id,
        Some((&host, port, &mac[..], &consent_ts)),
    )?;
    audit::record(
        conn,
        "gateway_route_added",
        None,
        None,
        &format!("prefix={prefix} provider={provider_id} custom_origin={host}"),
    )?;
    Ok(())
}

fn insert_route(
    conn: &Connection,
    prefix: &str,
    provider_id: &str,
    custom: Option<(&str, u16, &[u8], &str)>,
) -> Result<()> {
    let now = clock::now_rfc3339();
    let (origin, port, mac, consent) = match custom {
        Some((o, p, m, c)) => (Some(o), Some(p as i64), Some(m), Some(c)),
        None => (None, None, None, None),
    };
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO gateway_routes
            (route_prefix, provider_id, enabled, custom_origin, custom_origin_port,
             custom_origin_mac, custom_origin_consent_at, created_at, updated_at)
         VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![prefix, provider_id, origin, port, mac, consent, now],
    )?;
    if inserted == 0 {
        return Err(CoreError::AlreadyExists {
            kind: "gateway route",
            ident: prefix.to_string(),
        });
    }
    Ok(())
}

pub fn remove_route(conn: &Connection, prefix: &str) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM gateway_routes WHERE route_prefix = ?1",
        params![prefix],
    )?;
    if n > 0 {
        audit::record(
            conn,
            "gateway_route_removed",
            None,
            None,
            &format!("prefix={prefix}"),
        )?;
    }
    Ok(n > 0)
}

pub fn set_route_enabled(conn: &Connection, prefix: &str, enabled: bool) -> Result<bool> {
    let n = conn.execute(
        "UPDATE gateway_routes SET enabled = ?2, updated_at = ?3 WHERE route_prefix = ?1",
        params![prefix, enabled as i64, clock::now_rfc3339()],
    )?;
    Ok(n > 0)
}

/// Create a project link: a fresh 128-bit CSPRNG slug (never name-derived,
/// SI-4) scoping `/p/<slug>/<route>` traffic to the project.
pub fn add_project_link(conn: &Connection, project_id: &str, prefix: &str) -> Result<String> {
    let slug = hex_lower(&crypto::random_bytes(16));
    let n = conn.execute(
        "INSERT OR IGNORE INTO gateway_project_links
            (link_slug, project_id, route_prefix, created_at)
         SELECT ?1, ?2, ?3, ?4
         WHERE EXISTS (SELECT 1 FROM gateway_routes WHERE route_prefix = ?3)",
        params![slug, project_id, prefix, clock::now_rfc3339()],
    )?;
    if n == 0 {
        // Either the route does not exist or the (project, route) pair is
        // already linked.
        let route_exists: bool = conn
            .query_row(
                "SELECT 1 FROM gateway_routes WHERE route_prefix = ?1",
                params![prefix],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !route_exists {
            return Err(CoreError::NotFound {
                kind: "gateway route",
                ident: prefix.to_string(),
            });
        }
        return Err(CoreError::AlreadyExists {
            kind: "gateway project link",
            ident: format!("{project_id}:{prefix}"),
        });
    }
    audit::record(
        conn,
        "gateway_project_linked",
        Some(project_id),
        None,
        &format!("prefix={prefix}"),
    )?;
    Ok(slug)
}

pub fn remove_project_link(conn: &Connection, project_id: &str, prefix: &str) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM gateway_project_links WHERE project_id = ?1 AND route_prefix = ?2",
        params![project_id, prefix],
    )?;
    if n > 0 {
        audit::record(
            conn,
            "gateway_project_unlinked",
            Some(project_id),
            None,
            &format!("prefix={prefix}"),
        )?;
    }
    Ok(n > 0)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A resolved upstream origin (always https/443 by validation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamOrigin {
    pub host: String,
    pub port: u16,
}

/// Why a route cannot forward right now (both answer 503, but status
/// surfaces them differently).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unforwardable {
    /// Custom route, no MAC key in memory (vault locked since boot).
    MacKeyUnavailable,
    /// Custom route whose stored MAC does not verify — a tampered or
    /// corrupted row. Never forwarded.
    MacMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    Ready(UpstreamOrigin),
    Unforwardable(Unforwardable),
}

#[derive(Debug, Clone)]
pub struct Route {
    pub prefix: String,
    pub provider_id: String,
    pub target: RouteTarget,
    pub custom: bool,
    /// Bounded usage-extraction shape for this provider ("" = none).
    pub usage_shape: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    pub project_id: String,
    pub route_prefix: String,
    pub link_slug: String,
}

/// An immutable, validated in-memory snapshot of the route configuration.
/// The forwarding path only ever consults a snapshot — never the database.
#[derive(Debug, Default)]
pub struct RouteTable {
    routes: HashMap<String, Route>,
    links: HashMap<String, LinkInfo>,
    /// Routes present in the DB but not loadable (unknown provider, provider
    /// without a `[gateway]` section, invalid origin). Surfaced via status;
    /// requests for them 404 like any unknown prefix.
    pub skipped: Vec<(String, String)>,
    /// Routes present but switched off. They match nothing (404, exactly
    /// like a removed route); the count exists so status can tell
    /// "disabled" apart from "gone".
    pub disabled: usize,
}

impl RouteTable {
    pub fn route(&self, prefix: &str) -> Option<&Route> {
        self.routes.get(prefix)
    }
    pub fn link(&self, slug: &str) -> Option<&LinkInfo> {
        self.links.get(slug)
    }
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
    pub fn len(&self) -> usize {
        self.routes.len()
    }
    pub fn iter_routes(&self) -> impl Iterator<Item = &Route> {
        self.routes.values()
    }

    /// Insert a pre-built route. Exposed for tests ONLY so integration tests
    /// can point routes at synthetic loopback upstreams: `load_route_table`
    /// refuses loopback origins (SSRF policy), which is exactly the behavior
    /// the production path must keep, so tests construct the snapshot
    /// directly rather than weakening the policy for everyone.
    #[doc(hidden)]
    pub fn insert_for_test(&mut self, route: Route) {
        self.routes.insert(route.prefix.clone(), route);
    }

    /// Insert a pre-built project link. Tests only, same rationale.
    #[doc(hidden)]
    pub fn insert_link_for_test(&mut self, link: LinkInfo) {
        self.links.insert(link.link_slug.clone(), link);
    }
}

/// Load and validate a route snapshot. `mac_key` is the vault-derived route
/// MAC key if one has been pushed this boot; without it, custom routes load
/// as `Unforwardable::MacKeyUnavailable` (503) while manifest routes forward
/// normally (ADR 0019 D3 locked-startup behavior).
pub fn load_route_table(conn: &Connection, mac_key: Option<&SecretBytes>) -> Result<RouteTable> {
    let vault_id = vault_id_of(conn)?;
    let mut table = RouteTable::default();

    struct RouteRow {
        prefix: String,
        provider_id: String,
        enabled: bool,
        origin: Option<String>,
        port: Option<i64>,
        mac: Option<Vec<u8>>,
        consent: Option<String>,
    }
    let mut stmt = conn.prepare(
        "SELECT route_prefix, provider_id, enabled, custom_origin, custom_origin_port,
                custom_origin_mac, custom_origin_consent_at
         FROM gateway_routes",
    )?;
    let rows: Vec<RouteRow> = stmt
        .query_map([], |r| {
            Ok(RouteRow {
                prefix: r.get(0)?,
                provider_id: r.get(1)?,
                enabled: r.get::<_, i64>(2)? != 0,
                origin: r.get(3)?,
                port: r.get(4)?,
                mac: r.get(5)?,
                consent: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;

    for row in rows {
        let RouteRow {
            prefix,
            provider_id,
            enabled,
            origin,
            port,
            mac,
            consent,
        } = row;
        if !enabled {
            table.disabled += 1;
            continue; // disabled routes match nothing (404)
        }
        // A tampered prefix (e.g. rewritten to a reserved segment) must not
        // shadow the listener's own paths.
        if validate_route_prefix(&prefix).is_err() {
            table.skipped.push((prefix, "invalid route prefix".into()));
            continue;
        }
        let usage_shape = providers::find(&provider_id)
            .and_then(|m| m.gateway.as_ref())
            .map(|g| g.usage_shape.clone())
            .unwrap_or_default();

        let route = match (origin, port, mac, consent) {
            (None, None, None, None) => {
                // Manifest route: the compiled-in manifest is the trust root.
                let Some(manifest) = providers::find(&provider_id) else {
                    table
                        .skipped
                        .push((prefix, format!("unknown provider '{provider_id}'")));
                    continue;
                };
                let Some(gateway) = &manifest.gateway else {
                    table.skipped.push((
                        prefix,
                        format!("provider '{provider_id}' declares no gateway origin"),
                    ));
                    continue;
                };
                let Some(first) = gateway.origins.first() else {
                    table
                        .skipped
                        .push((prefix, format!("provider '{provider_id}' has no origins")));
                    continue;
                };
                let (host, port) = match validate_origin(first) {
                    Ok(hp) => hp,
                    Err(e) => {
                        table
                            .skipped
                            .push((prefix, format!("manifest origin: {e}")));
                        continue;
                    }
                };
                Route {
                    prefix: prefix.clone(),
                    provider_id,
                    target: RouteTarget::Ready(UpstreamOrigin { host, port }),
                    custom: false,
                    usage_shape,
                }
            }
            (Some(origin_host), Some(port_i), Some(stored_mac), Some(consent_ts)) => {
                let port = match u16::try_from(port_i) {
                    Ok(p) => p,
                    Err(_) => {
                        table.skipped.push((prefix, "invalid custom port".into()));
                        continue;
                    }
                };
                // Re-run the full origin policy over the stored value BEFORE
                // even considering the MAC (defense in depth: a valid MAC
                // over a now-denied origin still must not forward).
                if let Err(e) = validate_origin(&format!("https://{origin_host}")) {
                    table.skipped.push((prefix, format!("custom origin: {e}")));
                    continue;
                }
                let target = match mac_key {
                    None => RouteTarget::Unforwardable(Unforwardable::MacKeyUnavailable),
                    Some(key) => {
                        let expected = route_mac(
                            key,
                            &vault_id,
                            &provider_id,
                            &origin_host,
                            port,
                            &consent_ts,
                        )?;
                        use subtle::ConstantTimeEq;
                        if stored_mac.len() == 32
                            && expected[..].ct_eq(&stored_mac[..]).unwrap_u8() == 1
                        {
                            RouteTarget::Ready(UpstreamOrigin {
                                host: origin_host.clone(),
                                port,
                            })
                        } else {
                            RouteTarget::Unforwardable(Unforwardable::MacMismatch)
                        }
                    }
                };
                Route {
                    prefix: prefix.clone(),
                    provider_id,
                    target,
                    custom: true,
                    usage_shape,
                }
            }
            _ => {
                // Unrepresentable under the CHECK constraints, but never
                // trust the DB shape.
                table
                    .skipped
                    .push((prefix, "malformed custom route row".into()));
                continue;
            }
        };
        table.routes.insert(prefix, route);
    }

    let mut stmt =
        conn.prepare("SELECT link_slug, project_id, route_prefix FROM gateway_project_links")?;
    let links: Vec<(String, String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (slug, project_id, route_prefix) in links {
        table.links.insert(
            slug.clone(),
            LinkInfo {
                project_id,
                route_prefix,
                link_slug: slug,
            },
        );
    }
    Ok(table)
}

/// The service's live route state: an immutable snapshot swapped atomically,
/// change detection via `PRAGMA data_version` on a dedicated long-lived
/// connection, and last-known-good retention when the database is missing,
/// busy, or at a different schema version (forwarding NEVER stops because
/// persistence or configuration reads degrade — SI-12's configuration twin).
pub struct RouteState {
    db_path: PathBuf,
    mac_key: Mutex<Option<SecretBytes>>,
    table: RwLock<Arc<RouteTable>>,
    poll_conn: Mutex<Option<Connection>>,
    last_data_version: AtomicI64,
    degraded: AtomicBool,
}

impl RouteState {
    /// A state holding a fixed snapshot with no database behind it. Tests
    /// only: production always loads through `db::open_at_current_version`.
    #[doc(hidden)]
    pub fn from_table_for_test(table: RouteTable) -> Self {
        Self {
            db_path: PathBuf::from("/nonexistent/tethra-test-vault.db"),
            mac_key: Mutex::new(None),
            table: RwLock::new(Arc::new(table)),
            poll_conn: Mutex::new(None),
            last_data_version: AtomicI64::new(-1),
            degraded: AtomicBool::new(false),
        }
    }

    /// Create the state and attempt an initial load. A failed initial load
    /// (no DB yet, locked vault, schema drift) yields an EMPTY last-known-
    /// good table and the degraded flag — the listener still serves (404s).
    pub fn new(db_path: &Path) -> Self {
        let state = Self {
            db_path: db_path.to_path_buf(),
            mac_key: Mutex::new(None),
            table: RwLock::new(Arc::new(RouteTable::default())),
            poll_conn: Mutex::new(None),
            last_data_version: AtomicI64::new(-1),
            degraded: AtomicBool::new(false),
        };
        state.reload();
        state
    }

    pub fn table(&self) -> Arc<RouteTable> {
        self.table.read().expect("route table lock").clone()
    }

    /// Route-configuration reads currently failing (DB missing/busy/wrong
    /// schema); forwarding continues on the last-known-good snapshot.
    pub fn degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Install (or clear) the vault-derived route MAC key and re-resolve
    /// custom routes. The key arrives only over the authenticated control
    /// channel (SI-21); it is retained until process exit or revocation —
    /// unlike the fingerprint key it verifies route integrity only, which is
    /// why "locked SINCE BOOT" is the custom-route outage window.
    pub fn set_mac_key(&self, key: Option<SecretBytes>) {
        *self.mac_key.lock().expect("mac key lock") = key;
        self.reload();
    }

    /// Cheap change check; reloads only when another connection committed.
    pub fn reload_if_changed(&self) {
        let mut guard = self.poll_conn.lock().expect("poll conn lock");
        let version = guard.as_ref().and_then(|c| {
            c.query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
                .ok()
        });
        match version {
            Some(v) => {
                if self.last_data_version.swap(v, Ordering::Relaxed) != v {
                    drop(guard);
                    self.reload();
                }
            }
            None => {
                // No polling connection (or it went stale): try to establish
                // one and do a full reload.
                *guard = db::open_at_current_version(&self.db_path).ok();
                if let Some(conn) = guard.as_ref() {
                    if let Ok(v) = conn.query_row("PRAGMA data_version", [], |r| r.get(0)) {
                        self.last_data_version.store(v, Ordering::Relaxed);
                    }
                }
                drop(guard);
                self.reload();
            }
        }
    }

    /// Full reload through a short-lived, schema-checked connection. On any
    /// failure the previous snapshot stays installed.
    pub fn reload(&self) {
        let mac_key = self.mac_key.lock().expect("mac key lock").clone();
        let loaded = db::open_at_current_version(&self.db_path)
            .and_then(|conn| load_route_table(&conn, mac_key.as_ref()));
        match loaded {
            Ok(table) => {
                *self.table.write().expect("route table lock") = Arc::new(table);
                self.degraded.store(false, Ordering::Relaxed);
            }
            Err(_) => {
                self.degraded.store(true, Ordering::Relaxed);
            }
        }
    }
}
