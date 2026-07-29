//! Structural Git configuration isolation (ADR 0027).
//!
//! # Why this module exists
//!
//! Git is not a passive reader. A repository's own `.git/config` — a file
//! the attacker controls in any repository the user clones, extracts, or is
//! handed — can name programs Git executes during commands that look
//! read-only. The previous defence ([`crate::gitrepo`]'s `-c key=value`
//! overrides) was an **enumeration**: it listed the keys known to launch a
//! program and neutralised those. An enumeration cannot be complete against
//! a file the attacker writes, and it was not: `log.showSignature` plus
//! `gpg.program` were missing, and `git log -p` against a commit carrying a
//! `gpgsig` header ran the repository's chosen program as the user.
//!
//! There is no environment variable that switches off repository-local
//! configuration. `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_SYSTEM` and
//! `GIT_CONFIG_GLOBAL` cover the system and global files only; the
//! repository's own config *is* `$GIT_DIR/config`, and it is read because
//! `$GIT_DIR` is the repository.
//!
//! So this module changes `$GIT_DIR` instead. It builds a **sealed Git
//! directory**: a throwaway directory Tethra owns, containing only
//!
//! * a configuration file Tethra wrote,
//! * `objects/info/alternates` pointing at the real object store,
//! * copies of the refs, `HEAD`, and (when needed) the index.
//!
//! Git is then run with `--git-dir=<sealed>`. The repository's `config`,
//! `config.worktree`, and anything they `include` are not part of the
//! repository Git is looking at, so they cannot participate at all — not
//! for keys we thought of, and not for keys added by a future Git.
//!
//! Objects are shared through `alternates`, which is Git's own read-only
//! object-sharing mechanism: the sealed directory's own `objects/` is the
//! *primary* (writable) store, so anything Git chooses to write lands in
//! the throwaway directory and never in the user's repository.
//!
//! # What is deliberately not copied
//!
//! `config`, `config.worktree`, `info/attributes`, `info/grafts`, and hooks.
//! A `.gitattributes` file inside the tree may still name a diff driver or
//! filter, but the driver's *definition* (`diff.<name>.command`,
//! `filter.<name>.clean`, …) lives in configuration that is now Tethra's, so
//! the name resolves to nothing. [`crate::gitrepo`] additionally passes
//! `--no-ext-diff --no-textconv`, and keeps its `-c` overrides as a second,
//! independent layer.
//!
//! # Failing safely
//!
//! A repository whose format this module cannot faithfully reproduce
//! (an `extensions.*` key outside the validated allowlist, a ref set beyond
//! the copy bounds) is **refused**, loudly. It is never silently retried
//! against the repository's own configuration, because that is precisely
//! the input this module exists to distrust.

use crate::error::{CoreError, Result};
use crate::gitsafe::{self, RepoLayout};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Largest `config` file this module will read as data.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Largest `packed-refs` file copied into a seal.
pub const MAX_PACKED_REFS_BYTES: u64 = 64 * 1024 * 1024;
/// Largest single loose ref file copied into a seal.
pub const MAX_REF_FILE_BYTES: u64 = 64 * 1024;
/// How many loose ref files a seal will copy before refusing.
pub const MAX_REF_FILES: usize = 20_000;
/// Total loose-ref bytes a seal will copy before refusing.
pub const MAX_REF_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
/// Largest `HEAD` (or any per-worktree pointer file) copied into a seal.
pub const MAX_HEAD_BYTES: u64 = 64 * 1024;
/// Largest `reftable/` payload copied into a seal.
pub const MAX_REFTABLE_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// How many `reftable/` files a seal will copy before refusing.
pub const MAX_REFTABLE_FILES: usize = 10_000;
/// How deep the alternates chain is followed.
pub const MAX_ALTERNATE_HOPS: usize = 8;

/// `extensions.*` keys this module knows how to reproduce faithfully in a
/// sealed directory, with the exact values it accepts. Anything else means
/// the repository uses a format we cannot mirror, and sealing refuses.
///
/// Keys are compared lower-cased, because Git configuration key names are
/// case-insensitive.
const ALLOWED_EXTENSIONS: &[(&str, &[&str])] = &[
    ("objectformat", &["sha1", "sha256"]),
    ("compatobjectformat", &["sha1", "sha256"]),
    ("refstorage", &["files", "reftable"]),
    // Declares that Git should read `config.worktree`. The seal never
    // writes one, so honouring the flag is a no-op; it is allowlisted so
    // that ordinary multi-worktree repositories are not refused.
    ("worktreeconfig", &["true", "false"]),
    // Git's own placeholder extension, used by its test suite.
    ("noop", &["true", "false"]),
    ("noop-v1", &["true", "false"]),
];

/// Which optional parts of the repository a sealed directory needs.
///
/// Refs and `HEAD` are always sealed — Git refuses to treat a directory as
/// a repository without them. The index is copied only for the commands
/// that read it, because it is the one part that can be large.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SealParts {
    /// Copy `.git/index` so `diff --cached`, `show :path` and
    /// `cat-file :path` can resolve index entries.
    pub index: bool,
}

impl SealParts {
    /// Refs and `HEAD` only — enough for `rev-parse` and `log`.
    pub fn refs_only() -> Self {
        SealParts { index: false }
    }

    /// Also copy the index, for the staged-content commands.
    pub fn with_index() -> Self {
        SealParts { index: true }
    }
}

/// A throwaway Git directory that reproduces a repository's *content*
/// while excluding its *configuration*.
///
/// Removed from disk when dropped. Callers pass [`SealedRepo::git_dir`] to
/// Git as `--git-dir`.
#[derive(Debug)]
pub struct SealedRepo {
    dir: PathBuf,
    work_tree: PathBuf,
}

impl Drop for SealedRepo {
    fn drop(&mut self) {
        // Best effort: the seal holds no secret material (refs and HEAD are
        // object ids), and the directory is inside the user's own temp dir.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl SealedRepo {
    /// The sealed Git directory to pass as `--git-dir`.
    pub fn git_dir(&self) -> &Path {
        &self.dir
    }

    /// The work-tree root the seal was built from.
    pub fn work_tree(&self) -> &Path {
        &self.work_tree
    }
}

/// Read a file with a byte cap, refusing symlinks.
///
/// A symlinked `config`/`HEAD`/ref inside a hostile repository must not let
/// the seal read an arbitrary file elsewhere on disk.
fn read_capped_nofollow(path: &Path, cap: u64) -> Result<Option<Vec<u8>>> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CoreError::Io(e)),
    };
    if meta.file_type().is_symlink() {
        return Err(CoreError::InvalidInput(format!(
            "refusing to seal {}: it is a symbolic link, and a repository must not \
             redirect Tethra's reads outside itself",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Ok(None);
    }
    if meta.len() > cap {
        return Err(CoreError::InvalidInput(format!(
            "refusing to seal {}: {} bytes exceeds the {cap}-byte limit",
            path.display(),
            meta.len()
        )));
    }
    Ok(Some(std::fs::read(path)?))
}

/// One `section.key = value` triple from a Git configuration file.
struct ConfigEntry {
    section: String,
    key: String,
    value: String,
}

/// Parse a Git configuration file far enough to read `core.*` and
/// `extensions.*`.
///
/// This is a **data** reader, not an evaluator: `include.path` and
/// `includeIf` are deliberately not followed, and no value is ever used as
/// a command. It only has to be accurate enough to decide whether the
/// repository's format is one the seal can reproduce; when it is unsure it
/// reports the key, and the caller refuses.
fn parse_config(text: &str) -> Vec<ConfigEntry> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut subsection = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let head = rest.split(']').next().unwrap_or("").trim();
            let mut parts = head.splitn(2, '"');
            section = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            subsection = parts
                .next()
                .and_then(|s| s.rsplit_once('"').map(|(a, _)| a.to_string()))
                .unwrap_or_default();
            // `[section "sub"]` and `[section.sub]` are equivalent spellings.
            if subsection.is_empty() {
                if let Some((a, b)) = section.split_once('.') {
                    subsection = b.to_string();
                    section = a.to_string();
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            // A bare key is boolean-true in Git's syntax.
            out.push(ConfigEntry {
                section: section.clone(),
                key: line.trim().to_ascii_lowercase(),
                value: "true".to_string(),
            });
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        let key = key.trim().to_ascii_lowercase();
        let key = if subsection.is_empty() {
            key
        } else {
            format!("{subsection}.{key}")
        };
        out.push(ConfigEntry {
            section: section.clone(),
            key,
            value: value.to_string(),
        });
    }
    out
}

/// The repository format facts a seal must reproduce.
#[derive(Debug)]
struct RepoFormat {
    version: u32,
    object_format: Option<String>,
    compat_object_format: Option<String>,
    reftable: bool,
}

/// Read the repository's format from its configuration, refusing anything
/// the seal cannot mirror faithfully.
fn read_format(common_dir: &Path) -> Result<RepoFormat> {
    let mut format = RepoFormat {
        version: 0,
        object_format: None,
        compat_object_format: None,
        reftable: false,
    };
    let Some(bytes) = read_capped_nofollow(&common_dir.join("config"), MAX_CONFIG_BYTES)? else {
        return Ok(format);
    };
    let text = String::from_utf8_lossy(&bytes);
    for entry in parse_config(&text) {
        match entry.section.as_str() {
            "core" if entry.key == "repositoryformatversion" => {
                format.version = entry.value.trim().parse().map_err(|_| {
                    CoreError::InvalidInput(format!(
                        "refusing to read this repository safely: it declares \
                         core.repositoryformatversion = {:?}, which Tethra does not recognise",
                        entry.value
                    ))
                })?;
            }
            "extensions" => {
                let value = entry.value.trim().to_ascii_lowercase();
                let allowed = ALLOWED_EXTENSIONS
                    .iter()
                    .find(|(name, _)| *name == entry.key.as_str());
                let Some((_, values)) = allowed else {
                    return Err(CoreError::InvalidInput(format!(
                        "refusing to read this repository safely: it uses the Git extension \
                         '{}', which Tethra cannot reproduce in an isolated directory. \
                         Tethra will not fall back to running Git against this repository's \
                         own configuration.",
                        entry.key
                    )));
                };
                if !values.contains(&value.as_str()) {
                    return Err(CoreError::InvalidInput(format!(
                        "refusing to read this repository safely: extensions.{} = {:?} is not a \
                         value Tethra can reproduce in an isolated directory",
                        entry.key, entry.value
                    )));
                }
                match entry.key.as_str() {
                    "objectformat" => format.object_format = Some(value),
                    "compatobjectformat" => format.compat_object_format = Some(value),
                    "refstorage" => format.reftable = value == "reftable",
                    _ => {}
                }
            }
            _ => {}
        }
    }
    if format.version > 1 {
        return Err(CoreError::InvalidInput(format!(
            "refusing to read this repository safely: core.repositoryformatversion = {} is \
             newer than Tethra understands",
            format.version
        )));
    }
    Ok(format)
}

/// Create the seal directory itself: owner-only, and never reusing an
/// existing path.
fn create_seal_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("tethra-gitseal-{}", Uuid::new_v4()));
    // `create_dir` (not `create_dir_all`) fails if the path already exists,
    // so a pre-planted directory can never be adopted.
    std::fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// Write the seal's own configuration — the whole point of the module.
fn write_sealed_config(dir: &Path, format: &RepoFormat) -> Result<()> {
    let declares_extension =
        format.object_format.is_some() || format.compat_object_format.is_some() || format.reftable;
    let version = if declares_extension { 1 } else { 0 };
    let mut config = String::new();
    config.push_str("# Written by Tethra. This directory is a throwaway, isolated view of a\n");
    config.push_str("# repository's CONTENT. The repository's own configuration is deliberately\n");
    config.push_str("# absent so that it cannot name a program for Git to run.\n");
    config.push_str("[core]\n");
    config.push_str(&format!("\trepositoryformatversion = {version}\n"));
    config.push_str("\tbare = true\n");
    config.push_str("\tlogAllRefUpdates = false\n");
    // No global attributes or excludes file may be consulted either.
    config.push_str(&format!(
        "\tattributesFile = {}\n\texcludesFile = {}\n",
        crate::gitrepo::null_path(),
        crate::gitrepo::null_path()
    ));
    // Nothing in a read-only view should ever trigger background repacking.
    config.push_str("[gc]\n\tauto = 0\n\tautoDetach = false\n");
    config.push_str("[maintenance]\n\tauto = false\n");
    config.push_str("[fetch]\n\twriteCommitGraph = false\n");
    if declares_extension {
        config.push_str("[extensions]\n");
        if let Some(v) = &format.object_format {
            config.push_str(&format!("\tobjectFormat = {v}\n"));
        }
        if let Some(v) = &format.compat_object_format {
            config.push_str(&format!("\tcompatObjectFormat = {v}\n"));
        }
        if format.reftable {
            config.push_str("\trefStorage = reftable\n");
        }
    }
    std::fs::write(dir.join("config"), config)?;
    Ok(())
}

/// Point the seal's object store at the repository's, following any
/// alternates the repository itself declares.
fn write_alternates(dir: &Path, common_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir.join("objects/info"))?;
    let mut lines: Vec<String> = Vec::new();
    let mut queue = vec![common_dir.join("objects")];
    let mut hops = 0usize;
    while let Some(objects) = queue.pop() {
        if hops >= MAX_ALTERNATE_HOPS {
            break;
        }
        hops += 1;
        let text = objects.display().to_string();
        if lines.contains(&text) {
            continue;
        }
        lines.push(text);
        // A repository sharing objects with another (`clone --shared`)
        // records that in its own alternates file; the seal must carry the
        // whole chain or history reads come back short.
        if let Some(bytes) =
            read_capped_nofollow(&objects.join("info/alternates"), MAX_CONFIG_BYTES)?
        {
            for line in String::from_utf8_lossy(&bytes).lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let candidate = PathBuf::from(line);
                queue.push(if candidate.is_absolute() {
                    candidate
                } else {
                    objects.join(candidate)
                });
            }
        }
    }
    std::fs::write(
        dir.join("objects/info/alternates"),
        format!("{}\n", lines.join("\n")),
    )?;
    Ok(())
}

/// Copy a directory tree of small files under explicit count and byte caps.
fn copy_tree_bounded(
    from: &Path,
    to: &Path,
    max_files: usize,
    max_total: u64,
    max_each: u64,
    what: &str,
) -> Result<()> {
    if !from.is_dir() {
        return Ok(());
    }
    let mut files = 0usize;
    let mut total = 0u64;
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let dir = from.join(&rel);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let child_rel = rel.join(&name);
            let meta = match std::fs::symlink_metadata(entry.path()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                // A symlinked ref could point anywhere; skipping it is
                // honest (the ref simply is not in the sealed view) and is
                // far better than following it out of the repository.
                continue;
            }
            if meta.is_dir() {
                stack.push(child_rel);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            files += 1;
            total += meta.len();
            if files > max_files || total > max_total || meta.len() > max_each {
                return Err(CoreError::InvalidInput(format!(
                    "refusing to read this repository safely: its {what} exceed Tethra's \
                     isolation limits ({max_files} files / {max_total} bytes). Tethra will \
                     not fall back to running Git against this repository's own configuration."
                )));
            }
            let dest = to.join(&child_rel);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

/// Copy one file into the seal if it exists, under a byte cap.
fn copy_file_bounded(from: &Path, to: &Path, cap: u64) -> Result<bool> {
    match read_capped_nofollow(from, cap)? {
        Some(bytes) => {
            std::fs::write(to, bytes)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Build a sealed Git directory for the repository containing `start`.
///
/// Fails — rather than degrading to the repository's own configuration —
/// when the repository is not one this module can reproduce faithfully.
pub fn seal(start: &Path, parts: SealParts) -> Result<SealedRepo> {
    let canonical = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    let layout = gitsafe::discover(&canonical).ok_or_else(|| {
        CoreError::InvalidInput(format!(
            "{} is not inside a Git repository",
            start.display()
        ))
    })?;
    seal_layout(&layout, parts)
}

/// Build a sealed Git directory from an already-resolved layout.
pub fn seal_layout(layout: &RepoLayout, parts: SealParts) -> Result<SealedRepo> {
    let format = read_format(&layout.common_dir)?;
    let dir = create_seal_dir()?;
    // From here on, any failure must not leave a directory behind.
    let sealed = SealedRepo {
        dir,
        work_tree: layout.work_tree.clone(),
    };
    build(&sealed.dir, layout, &format, parts)?;
    Ok(sealed)
}

fn build(dir: &Path, layout: &RepoLayout, format: &RepoFormat, parts: SealParts) -> Result<()> {
    write_sealed_config(dir, format)?;
    write_alternates(dir, &layout.common_dir)?;

    // Git refuses to treat a directory as a repository unless `refs` exists,
    // even when the ref backend does not use it.
    std::fs::create_dir_all(dir.join("refs"))?;

    // `HEAD` is per-worktree: for a linked worktree it lives in the
    // worktree's own git dir, not the common dir.
    if !copy_file_bounded(
        &layout.git_dir.join("HEAD"),
        &dir.join("HEAD"),
        MAX_HEAD_BYTES,
    )? {
        return Err(CoreError::InvalidInput(format!(
            "refusing to read this repository safely: {} has no readable HEAD",
            layout.git_dir.display()
        )));
    }

    if format.reftable {
        copy_tree_bounded(
            &layout.common_dir.join("reftable"),
            &dir.join("reftable"),
            MAX_REFTABLE_FILES,
            MAX_REFTABLE_TOTAL_BYTES,
            MAX_REFTABLE_TOTAL_BYTES,
            "reftable files",
        )?;
    } else {
        copy_file_bounded(
            &layout.common_dir.join("packed-refs"),
            &dir.join("packed-refs"),
            MAX_PACKED_REFS_BYTES,
        )?;
        // Shared refs first, then the worktree's own (`refs/bisect`,
        // `refs/worktree`), which must win where both exist.
        copy_tree_bounded(
            &layout.common_dir.join("refs"),
            &dir.join("refs"),
            MAX_REF_FILES,
            MAX_REF_TOTAL_BYTES,
            MAX_REF_FILE_BYTES,
            "refs",
        )?;
        if layout.git_dir != layout.common_dir {
            copy_tree_bounded(
                &layout.git_dir.join("refs"),
                &dir.join("refs"),
                MAX_REF_FILES,
                MAX_REF_TOTAL_BYTES,
                MAX_REF_FILE_BYTES,
                "per-worktree refs",
            )?;
        }
    }

    // A shallow clone's history is truncated by this file; without it Git
    // walks into parents that are not present and fails.
    copy_file_bounded(
        &layout.common_dir.join("shallow"),
        &dir.join("shallow"),
        MAX_PACKED_REFS_BYTES,
    )?;

    if parts.index {
        copy_file_bounded(
            &layout.git_dir.join("index"),
            &dir.join("index"),
            gitsafe::MAX_INDEX_BYTES,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_subsection_spellings() {
        let entries = parse_config("[gpg \"ssh\"]\n\tprogram = x\n[gpg.x509]\n\tprogram = y\n");
        let keys: Vec<_> = entries
            .iter()
            .map(|e| format!("{}.{}", e.section, e.key))
            .collect();
        assert!(keys.contains(&"gpg.ssh.program".to_string()), "{keys:?}");
        assert!(keys.contains(&"gpg.x509.program".to_string()), "{keys:?}");
    }

    #[test]
    fn an_unknown_extension_is_refused_not_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tpartialClone = origin\n",
        )
        .unwrap();
        let err = read_format(dir.path()).expect_err("must refuse");
        let text = err.to_string();
        assert!(text.contains("partialclone"), "{text}");
        assert!(
            text.contains("will not fall back"),
            "the refusal must say it does not degrade to the repo's config: {text}"
        );
    }

    #[test]
    fn allowlisted_extensions_are_reproduced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectFormat = sha256\n",
        )
        .unwrap();
        let format = read_format(dir.path()).unwrap();
        assert_eq!(format.object_format.as_deref(), Some("sha256"));
    }

    #[test]
    fn a_symlinked_config_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", dir.path().join("config")).unwrap();
            let err = read_format(dir.path()).expect_err("a symlinked config must be refused");
            assert!(err.to_string().contains("symbolic link"), "{err}");
        }
    }

    #[test]
    fn the_sealed_config_never_contains_an_executable_key() {
        let dir = tempfile::tempdir().unwrap();
        let format = RepoFormat {
            version: 1,
            object_format: Some("sha256".into()),
            compat_object_format: None,
            reftable: true,
        };
        write_sealed_config(dir.path(), &format).unwrap();
        let text = std::fs::read_to_string(dir.path().join("config")).unwrap();
        for forbidden in [
            "fsmonitor",
            "hooksPath",
            "gpg",
            "showSignature",
            "external",
            "textconv",
            "helper",
            "askPass",
            "sshCommand",
            "editor",
            "pager",
            "filter",
            "include",
        ] {
            assert!(
                !text.contains(forbidden),
                "the sealed config must never mention {forbidden}: {text}"
            );
        }
        assert!(text.contains("refStorage = reftable"));
        assert!(text.contains("objectFormat = sha256"));
    }

    #[test]
    fn the_seal_directory_is_removed_on_drop() {
        let dir = create_seal_dir().unwrap();
        let sealed = SealedRepo {
            dir: dir.clone(),
            work_tree: PathBuf::from("/nonexistent"),
        };
        assert!(dir.exists());
        drop(sealed);
        assert!(!dir.exists(), "the seal must not outlive its handle");
    }
}
