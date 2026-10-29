//! The clone and rollback marker (DESIGN §D5, PROTOCOL.md §7.5).
//!
//! A device id must never act from two installations: its items are only
//! single-writer because one database allocates its seqs. Copying `vault.db`
//! (Migration Assistant, Time Machine, a copied `TETHRA_DIR`) or rolling it
//! back would break that silently. So every data directory with a mesh
//! identity holds `<data-dir>/mesh/identity.marker`:
//!
//! ```json
//! {"v":1,"device_id":"…","marker_nonce":"…","seq_high_water":128}
//! ```
//!
//! `marker_nonce` is random and also stored in `mesh_self`. `seq_high_water`
//! is the highest seq this installation may have used: before the store
//! mints a seq above it, it rewrites the marker with a mark one block of
//! [`SEQ_BLOCK`] seqs higher — temp file, fsync, rename, fsync of the
//! directory — so the fsync cost is paid once per block, not once per item.
//!
//! [`check`] then classifies a database against its directory's marker:
//! - **Missing**: the database was copied without its marker;
//! - **Mismatch**: the marker belongs to another identity, or to another
//!   copy of this one;
//! - **RolledBack**: the marker records seqs more than one block above what
//!   the database has, so the database is older than seqs it already used.
//!
//! A rollback within the current block, and a copy of the whole data
//! directory (database and marker together), are invisible here; the wire
//! catches those as forks (PROTOCOL.md §7.2). The marker holds no secret, but
//! it is written 0600 in a 0700 directory like everything else in the data
//! directory. On Windows the directory inherits the data directory's ACLs
//! and the directory itself is not fsynced (see `docs/mesh/KNOWN_LIMITATIONS.md`).

use super::dot::{DeviceId, MarkerNonce};
use super::error::MeshError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The directory under the data directory that holds mesh files.
pub const MESH_DIR: &str = "mesh";
/// The marker's file name inside [`MESH_DIR`].
pub const MARKER_FILE: &str = "identity.marker";
/// Seqs reserved by one marker write.
pub const SEQ_BLOCK: u64 = 64;
/// The marker never needs more than this; a larger file is not ours.
const MAX_MARKER_BYTES: u64 = 4096;
const MARKER_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkerContents {
    pub v: u32,
    pub device_id: DeviceId,
    pub marker_nonce: MarkerNonce,
    /// The highest seq this installation may have used.
    pub seq_high_water: u64,
}

impl MarkerContents {
    pub fn new(device_id: DeviceId, marker_nonce: MarkerNonce, seq_high_water: u64) -> Self {
        Self {
            v: MARKER_VERSION,
            device_id,
            marker_nonce,
            seq_high_water,
        }
    }

    /// Whether this marker vouches for `(device_id, nonce)`.
    pub fn matches(&self, device_id: &DeviceId, nonce: &MarkerNonce) -> bool {
        self.device_id == *device_id && self.marker_nonce == *nonce
    }
}

/// What a database's identity looks like against its directory's marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkerStatus {
    Ok,
    Missing,
    Mismatch,
    RolledBack,
}

impl MarkerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MarkerStatus::Ok => "ok",
            MarkerStatus::Missing => "missing",
            MarkerStatus::Mismatch => "mismatch",
            MarkerStatus::RolledBack => "rolled_back",
        }
    }

    /// Why a store must not mint, for errors and `status`.
    pub fn problem(&self) -> Option<&'static str> {
        match self {
            MarkerStatus::Ok => None,
            MarkerStatus::Missing => {
                Some("its identity marker is missing, so this database is probably a copy")
            }
            MarkerStatus::Mismatch => Some(
                "its identity marker belongs to another installation, so this database is probably a copy",
            ),
            MarkerStatus::RolledBack => Some(
                "its identity marker records items this database does not have, so the database was rolled back",
            ),
        }
    }

    pub fn to_error(self) -> Option<MeshError> {
        self.problem().map(MeshError::IdentityMismatch)
    }
}

/// `<data-dir>/mesh`.
pub fn mesh_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(MESH_DIR)
}

/// `<data-dir>/mesh/identity.marker`.
pub fn marker_path(data_dir: &Path) -> PathBuf {
    mesh_dir(data_dir).join(MARKER_FILE)
}

/// Read the marker. `Ok(None)` when there is none; an unreadable or
/// malformed file is an error, never "no marker".
pub fn read(data_dir: &Path) -> Result<Option<MarkerContents>, MeshError> {
    let path = marker_path(data_dir);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(MeshError::Storage("the identity marker cannot be read")),
    };
    if !meta.is_file() {
        return Err(MeshError::IdentityMismatch(
            "the identity marker is not a regular file",
        ));
    }
    if meta.len() > MAX_MARKER_BYTES {
        return Err(MeshError::IdentityMismatch(
            "the identity marker is malformed",
        ));
    }
    let bytes = std::fs::read(&path)
        .map_err(|_| MeshError::Storage("the identity marker cannot be read"))?;
    let contents: MarkerContents = serde_json::from_slice(&bytes)
        .map_err(|_| MeshError::IdentityMismatch("the identity marker is malformed"))?;
    if contents.v != MARKER_VERSION {
        return Err(MeshError::IdentityMismatch(
            "the identity marker has an unknown version",
        ));
    }
    Ok(Some(contents))
}

/// Classify the database's identity `(device_id, nonce)`, whose own log
/// reaches `last_seq` (`vv[self]`), against the directory's marker.
pub fn check(
    data_dir: &Path,
    device_id: &DeviceId,
    nonce: &MarkerNonce,
    last_seq: u64,
) -> Result<MarkerStatus, MeshError> {
    Ok(classify(
        read(data_dir)?.as_ref(),
        device_id,
        nonce,
        last_seq,
    ))
}

/// [`check`] on an already-read marker.
pub fn classify(
    marker: Option<&MarkerContents>,
    device_id: &DeviceId,
    nonce: &MarkerNonce,
    last_seq: u64,
) -> MarkerStatus {
    match marker {
        None => MarkerStatus::Missing,
        Some(m) if !m.matches(device_id, nonce) => MarkerStatus::Mismatch,
        // A mark is written one block ahead before the database uses the
        // block's first seq, so an honest database is never more than one
        // block behind its marker (a crash between the two leaves exactly
        // one block).
        Some(m) if m.seq_high_water > last_seq.saturating_add(SEQ_BLOCK) => {
            MarkerStatus::RolledBack
        }
        Some(_) => MarkerStatus::Ok,
    }
}

/// Write the marker atomically: a 0600 temp file in a 0700 `mesh/`
/// directory, fsync, rename over the marker, fsync the directory. When this
/// returns, the new mark is durable.
pub fn write(data_dir: &Path, contents: &MarkerContents) -> Result<(), MeshError> {
    let dir = mesh_dir(data_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|_| MeshError::Storage("the mesh directory cannot be created"))?;
    restrict_dir(&dir)?;
    let bytes = serde_json::to_vec(contents)
        .map_err(|_| MeshError::Storage("the identity marker cannot be encoded"))?;
    let path = dir.join(MARKER_FILE);
    let tmp = dir.join(format!(".{MARKER_FILE}.tmp-{}", MarkerNonce::random()));
    let result = write_synced(&tmp, &bytes).and_then(|()| {
        std::fs::rename(&tmp, &path)
            .map_err(|_| MeshError::Storage("the identity marker cannot be replaced"))
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    sync_dir(&dir)
}

/// What [`remove_if_owned`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkerRemoval {
    /// The marker named the wiped identity and was deleted.
    Removed,
    /// There was no marker.
    Absent,
    /// The marker names another identity (or is unreadable) and was left
    /// alone; it no longer vouches for anything in this database.
    LeftInPlace,
}

/// Delete the marker only when it names `device_id`. A marker for another
/// identity is somebody else's evidence and is never touched.
pub fn remove_if_owned(
    data_dir: &Path,
    device_id: Option<&DeviceId>,
) -> Result<MarkerRemoval, MeshError> {
    let current = match read(data_dir) {
        Ok(None) => return Ok(MarkerRemoval::Absent),
        Ok(Some(m)) => m,
        Err(_) => return Ok(MarkerRemoval::LeftInPlace),
    };
    if device_id != Some(&current.device_id) {
        return Ok(MarkerRemoval::LeftInPlace);
    }
    match std::fs::remove_file(marker_path(data_dir)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(MarkerRemoval::Absent),
        Err(_) => return Err(MeshError::Storage("the identity marker cannot be removed")),
    }
    sync_dir(&mesh_dir(data_dir))?;
    Ok(MarkerRemoval::Removed)
}

#[cfg(unix)]
fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), MeshError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| MeshError::Storage("the identity marker cannot be written"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| MeshError::Storage("the identity marker cannot be written"))
}

#[cfg(not(unix))]
fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), MeshError> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| MeshError::Storage("the identity marker cannot be written"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| MeshError::Storage("the identity marker cannot be written"))
}

#[cfg(unix)]
fn restrict_dir(dir: &Path) -> Result<(), MeshError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| MeshError::Storage("the mesh directory cannot be restricted"))
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) -> Result<(), MeshError> {
    // Windows: the directory inherits the per-user data directory's ACLs,
    // as the vault's own files do (KNOWN_LIMITATIONS).
    Ok(())
}

/// Make a rename or delete in `dir` durable.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), MeshError> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|_| MeshError::Storage("the mesh directory cannot be synced"))
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<(), MeshError> {
    // std cannot open a directory for syncing on Windows; NTFS journals the
    // rename itself (KNOWN_LIMITATIONS).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (DeviceId, MarkerNonce) {
        (
            DeviceId::from_bytes([7; 16]),
            MarkerNonce::from_bytes([9; 16]),
        )
    }

    #[test]
    fn write_then_read_round_trips_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let (d, n) = ids();
        let m = MarkerContents::new(d, n, 64);
        write(dir.path(), &m).unwrap();
        assert_eq!(read(dir.path()).unwrap(), Some(m));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let f = std::fs::metadata(marker_path(dir.path())).unwrap();
            assert_eq!(f.permissions().mode() & 0o777, 0o600);
            let md = std::fs::metadata(mesh_dir(dir.path())).unwrap();
            assert_eq!(md.permissions().mode() & 0o777, 0o700);
        }
        // Rewriting replaces it and leaves no temp files behind.
        write(dir.path(), &MarkerContents::new(d, n, 128)).unwrap();
        assert_eq!(read(dir.path()).unwrap().unwrap().seq_high_water, 128);
        let names: Vec<_> = std::fs::read_dir(mesh_dir(dir.path()))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(MARKER_FILE)]);
    }

    #[test]
    fn classification_covers_every_case() {
        let (d, n) = ids();
        let other_n = MarkerNonce::from_bytes([1; 16]);
        let other_d = DeviceId::from_bytes([2; 16]);
        assert_eq!(classify(None, &d, &n, 5), MarkerStatus::Missing);
        let m = MarkerContents::new(d, n, 64);
        assert_eq!(classify(Some(&m), &d, &n, 1), MarkerStatus::Ok);
        assert_eq!(
            classify(Some(&m), &d, &n, 0),
            MarkerStatus::Ok,
            "crash before seq 1"
        );
        assert_eq!(classify(Some(&m), &d, &other_n, 1), MarkerStatus::Mismatch);
        assert_eq!(classify(Some(&m), &other_d, &n, 1), MarkerStatus::Mismatch);
        let m = MarkerContents::new(d, n, 192);
        assert_eq!(classify(Some(&m), &d, &n, 128), MarkerStatus::Ok);
        assert_eq!(classify(Some(&m), &d, &n, 127), MarkerStatus::RolledBack);
        assert!(MarkerStatus::RolledBack.to_error().is_some());
        assert!(MarkerStatus::Ok.to_error().is_none());
    }

    #[test]
    fn malformed_or_foreign_files_are_errors_not_absence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(mesh_dir(dir.path())).unwrap();
        std::fs::write(marker_path(dir.path()), b"{not json").unwrap();
        assert!(matches!(
            read(dir.path()),
            Err(MeshError::IdentityMismatch(_))
        ));
        std::fs::write(
            marker_path(dir.path()),
            br#"{"v":1,"device_id":"07070707070707070707070707070707","marker_nonce":"09090909090909090909090909090909","seq_high_water":1,"extra":1}"#,
        )
        .unwrap();
        assert!(read(dir.path()).is_err(), "unknown fields are refused");
        std::fs::write(marker_path(dir.path()), vec![b' '; 5000]).unwrap();
        assert!(read(dir.path()).is_err(), "oversize is refused");
    }

    #[test]
    fn removal_only_touches_the_named_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (d, n) = ids();
        assert_eq!(
            remove_if_owned(dir.path(), Some(&d)).unwrap(),
            MarkerRemoval::Absent
        );
        write(dir.path(), &MarkerContents::new(d, n, 64)).unwrap();
        let other = DeviceId::from_bytes([3; 16]);
        assert_eq!(
            remove_if_owned(dir.path(), Some(&other)).unwrap(),
            MarkerRemoval::LeftInPlace
        );
        assert_eq!(
            remove_if_owned(dir.path(), None).unwrap(),
            MarkerRemoval::LeftInPlace
        );
        assert!(read(dir.path()).unwrap().is_some());
        assert_eq!(
            remove_if_owned(dir.path(), Some(&d)).unwrap(),
            MarkerRemoval::Removed
        );
        assert!(read(dir.path()).unwrap().is_none());
    }
}
