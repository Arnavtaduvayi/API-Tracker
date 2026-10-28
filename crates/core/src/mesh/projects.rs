//! Shared projects (Increment 06, DESIGN §D11).
//!
//! A **mesh project** is a replicated `project.meta` (id, name, archived,
//! merged_into; last-writer-wins). A **binding** maps one local project to one
//! mesh project, on this device only (`mesh_project_bindings`). Binding is
//! never automatic (MESH-SI-13): not by name, not by local project id (a
//! restored backup clones local ids). Sharing a project creates a mesh project
//! and binds the local one; other devices bind their own local project to it
//! explicitly. Mesh projects are never deleted: they are renamed, archived or
//! merged. A merge points the non-root at the root, the smaller id, and views
//! fold the non-root's counters into the root.

use super::dot::{DeviceId, MeshProjectId};
use super::error::MeshError;
use super::kinds::ProjectMeta;
use super::sign::SigningKeyPair;
use super::sqlite_store::SqliteStore;
use super::store::{Draft, HlcPolicy, MeshStore};
use super::views::ProjectValue;
use crate::error::{CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// The longest merge chain followed (merges are rare; a cycle cannot form
/// because a project only ever merges into a smaller id).
const MAX_MERGE_DEPTH: usize = 64;

/// One mesh project as `mesh project list` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeshProjectRow {
    pub mesh_project_id: MeshProjectId,
    pub name: String,
    pub archived: bool,
    pub merged_into: Option<MeshProjectId>,
    /// The project its counters fold into (itself unless merged).
    pub root: MeshProjectId,
    /// The local project bound to it on this device, if any.
    pub bound_local_project: Option<String>,
    pub bound_local_project_name: Option<String>,
    /// Devices that have published usage for it (a device's bindings are
    /// private to it; publishing is what the mesh can see).
    pub publishing_devices: Vec<DeviceId>,
}

fn not_found(ident: &str) -> CoreError {
    CoreError::NotFound {
        kind: "mesh project",
        ident: ident.to_owned(),
    }
}

fn invalid(msg: &'static str) -> CoreError {
    CoreError::InvalidInput(msg.into())
}

/// The value of mesh project `id` as this device sees it.
pub fn get(store: &SqliteStore, id: &MeshProjectId) -> Option<ProjectValue> {
    let state = store.state();
    state.projects.value(id, &state.roster).cloned()
}

/// Follow `merged_into` to the root.
pub fn root_of(store: &SqliteStore, id: &MeshProjectId) -> MeshProjectId {
    let mut cur = *id;
    for _ in 0..MAX_MERGE_DEPTH {
        match get(store, &cur).and_then(|p| p.merged_into) {
            Some(next) if next < cur => cur = next,
            _ => break,
        }
    }
    cur
}

/// Resolve a mesh project by its id, a unique prefix of at least 8 hex
/// characters, or its exact name (case-insensitive, unique).
pub fn resolve(store: &SqliteStore, ident: &str) -> Result<MeshProjectId> {
    let ident = ident.trim();
    let state = store.state();
    let all: Vec<(MeshProjectId, String)> = state
        .projects
        .values(&state.roster)
        .map(|(id, v)| (*id, v.name.clone()))
        .collect();
    let lower = ident.to_ascii_lowercase();
    if lower.len() >= 8 && lower.bytes().all(|c| c.is_ascii_hexdigit()) {
        let hits: Vec<_> = all
            .iter()
            .filter(|(id, _)| id.to_hex().starts_with(&lower))
            .collect();
        if hits.len() == 1 {
            return Ok(hits[0].0);
        }
    }
    let named: Vec<_> = all
        .iter()
        .filter(|(_, n)| n.eq_ignore_ascii_case(ident))
        .collect();
    match named.len() {
        1 => Ok(named[0].0),
        0 => Err(not_found(ident)),
        _ => Err(invalid(
            "several mesh projects have that name; use the id (`tethra mesh project list`)",
        )),
    }
}

fn binding_of(conn: &Connection, local_project_id: &str) -> Result<Option<MeshProjectId>> {
    let v: Option<String> = conn
        .query_row(
            "SELECT mesh_project_id FROM mesh_project_bindings WHERE local_project_id = ?1",
            [local_project_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(v.and_then(|s| MeshProjectId::parse(&s).ok()))
}

/// Every binding on this device: local project id → mesh project.
pub fn bindings(conn: &Connection) -> Result<BTreeMap<String, MeshProjectId>> {
    let mut st =
        conn.prepare("SELECT local_project_id, mesh_project_id FROM mesh_project_bindings")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (l, m) = row?;
        if let Ok(m) = MeshProjectId::parse(&m) {
            out.insert(l, m);
        }
    }
    Ok(out)
}

fn insert_binding(conn: &Connection, local: &str, mesh: &MeshProjectId) -> Result<()> {
    conn.execute(
        "INSERT INTO mesh_project_bindings (local_project_id, mesh_project_id, bound_at)
         VALUES (?1, ?2, ?3)",
        params![local, mesh.to_hex(), crate::clock::now_rfc3339()],
    )?;
    Ok(())
}

fn require_unbound(conn: &Connection, local_project_id: &str) -> Result<()> {
    if binding_of(conn, local_project_id)?.is_some() {
        return Err(invalid(
            "that local project is already bound to a mesh project; unbind it first",
        ));
    }
    Ok(())
}

fn mint_meta(store: &mut SqliteStore, signing: &SigningKeyPair, meta: ProjectMeta) -> Result<()> {
    let winner = {
        let state = store.state();
        state
            .projects
            .register(&meta.project)
            .and_then(|r| r.winning_hlc(&state.roster))
    };
    store.mint(signing, Draft::of(&meta, HlcPolicy::After(winner)))?;
    Ok(())
}

/// Share local project `local_project_id` (named `name`): a new mesh project
/// with that name, bound here. One transaction for the item and the binding.
pub fn share(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    local_project_id: &str,
    name: &str,
) -> Result<MeshProjectId> {
    require_unbound(store.connection(), local_project_id)?;
    let id = MeshProjectId::random();
    let meta = ProjectMeta {
        project: id,
        name: name.to_owned(),
        archived: false,
        merged_into: None,
    };
    let local = local_project_id.to_owned();
    store.mint_batch(signing, vec![Draft::of(&meta, HlcPolicy::Now)], |tx| {
        insert_binding(tx, &local, &id).map_err(|_| MeshError::Storage("binding the project"))
    })?;
    Ok(id)
}

/// Bind local project `local_project_id` to an existing mesh project.
pub fn bind(store: &SqliteStore, mesh: &MeshProjectId, local_project_id: &str) -> Result<()> {
    let p = get(store, mesh).ok_or_else(|| not_found(&mesh.to_hex()))?;
    if p.archived {
        return Err(invalid("that mesh project is archived"));
    }
    if let Some(root) = p.merged_into {
        return Err(CoreError::InvalidInput(format!(
            "that mesh project was merged into {}; bind that one instead",
            &root.to_hex()[..8]
        )));
    }
    require_unbound(store.connection(), local_project_id)?;
    insert_binding(store.connection(), local_project_id, mesh)
}

/// Remove this device's binding of a local project. Usage published so far
/// stays published; nothing new is attributed. Returns whether it was bound.
pub fn unbind(conn: &Connection, local_project_id: &str) -> Result<bool> {
    Ok(conn.execute(
        "DELETE FROM mesh_project_bindings WHERE local_project_id = ?1",
        [local_project_id],
    )? > 0)
}

pub fn rename(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    mesh: &MeshProjectId,
    name: &str,
) -> Result<()> {
    let p = get(store, mesh).ok_or_else(|| not_found(&mesh.to_hex()))?;
    mint_meta(
        store,
        signing,
        ProjectMeta {
            project: *mesh,
            name: name.trim().to_owned(),
            archived: p.archived,
            merged_into: p.merged_into,
        },
    )
}

pub fn archive(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    mesh: &MeshProjectId,
) -> Result<()> {
    let p = get(store, mesh).ok_or_else(|| not_found(&mesh.to_hex()))?;
    mint_meta(
        store,
        signing,
        ProjectMeta {
            project: *mesh,
            name: p.name,
            archived: true,
            merged_into: p.merged_into,
        },
    )
}

/// The caps defined on `mesh` (Increment 07 creates them).
pub fn cap_count(store: &SqliteStore, mesh: &MeshProjectId) -> usize {
    let state = store.state();
    state
        .cap_defs
        .values(&state.roster)
        .filter(|(_, d)| d.mesh_project_id == *mesh)
        .count()
}

/// Merge two duplicates of one real project: the one with the larger id
/// points at the smaller (the root), and views fold its counters into the
/// root. Refused when both have spend caps. Returns `(root, merged)`.
pub fn merge(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    a: &MeshProjectId,
    b: &MeshProjectId,
) -> Result<(MeshProjectId, MeshProjectId)> {
    let (ra, rb) = (root_of(store, a), root_of(store, b));
    if ra == rb {
        return Err(invalid("those mesh projects are already one project"));
    }
    for r in [ra, rb] {
        if get(store, &r).is_none() {
            return Err(not_found(&r.to_hex()));
        }
    }
    if cap_count(store, &ra) > 0 && cap_count(store, &rb) > 0 {
        return Err(invalid(
            "both projects have spend caps; lower one cap to 0 and archive that project first",
        ));
    }
    let (root, child) = if ra < rb { (ra, rb) } else { (rb, ra) };
    let p = get(store, &child).expect("checked");
    mint_meta(
        store,
        signing,
        ProjectMeta {
            project: child,
            name: p.name,
            archived: p.archived,
            merged_into: Some(root),
        },
    )?;
    Ok((root, child))
}

/// Every mesh project, with this device's binding and who publishes for it.
pub fn list(store: &SqliteStore) -> Result<Vec<MeshProjectRow>> {
    let conn = store.connection();
    let bound: BTreeMap<MeshProjectId, String> =
        bindings(conn)?.into_iter().map(|(l, m)| (m, l)).collect();
    let state = store.state();
    let mut publishing: BTreeMap<MeshProjectId, BTreeSet<DeviceId>> = BTreeMap::new();
    for (k, o, _) in state.usage.iter() {
        if state.roster.is_known(o) {
            publishing.entry(k.project).or_default().insert(*o);
        }
    }
    let mut out = Vec::new();
    for (id, v) in state.projects.values(&state.roster) {
        let local = bound.get(id).cloned();
        let local_name: Option<String> = match &local {
            Some(l) => conn
                .query_row("SELECT name FROM projects WHERE id = ?1", [l], |r| r.get(0))
                .optional()?,
            None => None,
        };
        out.push(MeshProjectRow {
            mesh_project_id: *id,
            name: v.name.clone(),
            archived: v.archived,
            merged_into: v.merged_into,
            root: root_of(store, id),
            bound_local_project: local,
            bound_local_project_name: local_name,
            publishing_devices: publishing
                .get(id)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default(),
        });
    }
    out.sort_by_key(|r| r.name.to_lowercase());
    Ok(out)
}
