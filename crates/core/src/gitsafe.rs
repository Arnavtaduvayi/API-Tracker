//! Non-executing Git repository inspection (ADR 0023).
//!
//! Everything a scan needs to know about a Git repository — is this path
//! inside a work tree, is a file tracked, is a file ignored — computed by
//! **reading bytes only**. No subprocess is spawned, so no repository-
//! controlled Git configuration (`core.fsmonitor`, hooks, filters,
//! textconv, diff drivers, aliases, pagers, editors, credential helpers,
//! submodule commands, `GIT_EXTERNAL_DIFF`, …) can turn a scan into code
//! execution.
//!
//! This module is the reason `envgov::discover` — the reader behind folder
//! selection, provider detection, dry-run planning, apply, undo and
//! diagnostics — spawns nothing at all. The `gitrepo` module still shells
//! out for the deliberate, user-invoked secret scanner, where it now runs
//! under [`crate::gitrepo::hardened`] argument and environment isolation.
//!
//! ## What is read
//!
//! * `.git` (directory, or a file containing `gitdir: <path>` for worktrees
//!   and submodules) to locate the work tree and the real Git directory.
//! * `.git/index` — the staging area, parsed as the documented `DIRC`
//!   binary format (versions 2, 3 and 4; SHA-1 and SHA-256 object ids).
//!   A path present in the index is `Tracked`.
//! * `.git/sharedindex.<oid>` — the other half of a **split index**. When
//!   `.git/index` carries the `link` extension its entries are name-less
//!   placeholders and the real paths live in the shared file, so the shared
//!   file is read and its delete bitmap applied. Without this a
//!   split-index repository reports every file untracked (RA-007).
//! * `.gitignore` files from the work-tree root down to the file's own
//!   directory, plus `.git/info/exclude`.
//!
//! ## What is deliberately NOT read
//!
//! * `core.excludesFile` (the user's global ignore file) and any other
//!   value from `.git/config`, `~/.gitconfig` or `/etc/gitconfig`. Ignore
//!   answers therefore reflect repository-local rules only; a file ignored
//!   solely by a global rule is reported `Untracked`, never `Ignored`.
//! * Commit history. "Has this file ever been committed?" requires walking
//!   the object database and is not answered here; callers that need it
//!   must ask for it explicitly (see [`crate::envgov::HistoryProbe`]).
//!
//! Both limitations are recorded in `docs/activity-onboarding/KNOWN_LIMITATIONS.md`.
//!
//! ## Bounds
//!
//! Every read is capped ([`MAX_INDEX_BYTES`], [`MAX_INDEX_PATH_BYTES`],
//! [`MAX_IGNORE_BYTES`], [`MAX_IGNORE_PATTERNS`], [`MAX_GITDIR_HOPS`]).
//! Exceeding a bound degrades the answer to "unknown" and is reported to
//! the caller — it never panics, never allocates without limit, and never
//! silently claims a clean result.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Largest `.git/index` this module will read (64 MiB). Beyond it the
/// tracked-file answer degrades to `Unknown`.
pub const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

/// Largest total path text retained from one index file (32 MiB).
///
/// [`MAX_INDEX_BYTES`] bounds the FILE, not the paths rebuilt out of it.
/// A version-4 index stores each path as "strip N bytes off the previous
/// path, then append this suffix", so an index whose every entry strips
/// nothing and appends one byte reconstructs O(n²) bytes of path from a
/// linear file: the auditor measured 764 MiB of live heap from 0.61 MiB of
/// input, and 11.9 GiB from 2.44 MiB (RA-008). Versions 2 and 3 store each
/// path whole and so can never exceed the file size, which is why this cap
/// only ever binds on prefix compression — a real repository (~500 000
/// paths at 64 bytes) stays far below it, and an amplifying one degrades to
/// `Unknown` with a reported limit instead of allocating.
pub const MAX_INDEX_PATH_BYTES: usize = 32 * 1024 * 1024;

/// Largest single ignore file this module will read (1 MiB).
pub const MAX_IGNORE_BYTES: u64 = 1024 * 1024;

/// Largest number of ignore patterns retained across all ignore files.
pub const MAX_IGNORE_PATTERNS: usize = 20_000;

/// How many `gitdir:` indirections to follow before giving up (linked
/// worktrees and submodules use one; a cycle must not hang the scan).
pub const MAX_GITDIR_HOPS: usize = 8;

/// How far up the tree [`discover`] looks for a repository root.
pub const MAX_DISCOVERY_ASCENT: usize = 64;

/// Where a repository lives, resolved without running Git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoLayout {
    /// The work-tree root — the directory that contains `.git`.
    pub work_tree: PathBuf,
    /// The real Git directory (`<work_tree>/.git`, or the target of a
    /// `gitdir:` pointer for linked worktrees and submodules).
    pub git_dir: PathBuf,
    /// For a linked worktree, the shared common directory that owns
    /// `info/exclude`; equal to `git_dir` for an ordinary repository.
    pub common_dir: PathBuf,
}

/// A path's relationship to the repository, as far as a non-executing
/// reader can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    /// Present in `.git/index`.
    Tracked,
    /// Not in the index and matched by a repository-local ignore rule.
    Ignored,
    /// Not in the index and not matched by any repository-local rule.
    Untracked,
    /// The index or the ignore rules could not be read within bounds, so
    /// no honest claim is possible.
    Unknown,
}

/// Why a [`RepoView`] could not answer completely. Surfaced to the user as
/// a scan warning rather than swallowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewLimit {
    /// `.git/index` was larger than [`MAX_INDEX_BYTES`].
    IndexTooLarge { bytes: u64 },
    /// `.git/index` exists but could not be read, or is not a format this
    /// reader understands.
    IndexUnreadable { why: String },
    /// Rebuilding the index's paths would have retained more than
    /// [`MAX_INDEX_PATH_BYTES`].
    IndexPathBudget,
    /// At least one ignore file exceeded [`MAX_IGNORE_BYTES`] and was skipped.
    IgnoreFileTooLarge { path: String },
    /// The pattern budget was exhausted; later rules were not loaded.
    IgnorePatternBudget,
}

impl ViewLimit {
    pub fn describe(&self) -> String {
        match self {
            // Every index limit degrades status to `Unknown`, not to
            // `Untracked`: saying "untracked" here would be the silent
            // clean answer this module exists to avoid (RA-007).
            ViewLimit::IndexTooLarge { bytes } => format!(
                "this repository's Git index is {bytes} bytes, over Tethra's {MAX_INDEX_BYTES}-byte \
                 read limit — whether files are committed is reported as unknown rather than guessed"
            ),
            ViewLimit::IndexUnreadable { why } => {
                format!("this repository's Git index could not be read ({why}) — whether files are \
                         committed is reported as unknown rather than guessed")
            }
            ViewLimit::IndexPathBudget => format!(
                "this repository's Git index expands to more than {MAX_INDEX_PATH_BYTES} bytes of \
                 file names — whether files are committed is reported as unknown rather than guessed"
            ),
            ViewLimit::IgnoreFileTooLarge { path } => {
                format!("{path} is over Tethra's {MAX_IGNORE_BYTES}-byte ignore-file limit and \
                         was not applied")
            }
            ViewLimit::IgnorePatternBudget => format!(
                "this repository has more than {MAX_IGNORE_PATTERNS} ignore rules; the remainder \
                 were not applied"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Repository discovery
// ---------------------------------------------------------------------------

/// Read a small file with a byte cap, without following a symlink at the
/// final component. Returns `None` when absent, oversized, or a symlink.
fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > cap {
        return None;
    }
    std::fs::read(path).ok()
}

/// Resolve a `.git` entry to the real Git directory.
///
/// `.git` is normally a directory. In a linked worktree or a submodule it
/// is a regular file whose contents are `gitdir: <path>` (absolute, or
/// relative to the file's own directory). Chains are followed up to
/// [`MAX_GITDIR_HOPS`].
fn resolve_git_dir(dot_git: &Path) -> Option<PathBuf> {
    let mut current = dot_git.to_path_buf();
    for _ in 0..MAX_GITDIR_HOPS {
        let meta = std::fs::symlink_metadata(&current).ok()?;
        if meta.is_dir() {
            return Some(current);
        }
        // A symlinked `.git` is legitimate; resolve it once through
        // metadata rather than refusing, but never read it as a file.
        if meta.file_type().is_symlink() {
            current = std::fs::canonicalize(&current).ok()?;
            continue;
        }
        if !meta.is_file() {
            return None;
        }
        let bytes = read_capped(&current, 64 * 1024)?;
        let text = String::from_utf8_lossy(&bytes);
        let target = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("gitdir:"))?
            .trim();
        if target.is_empty() {
            return None;
        }
        let target = PathBuf::from(target);
        current = if target.is_absolute() {
            target
        } else {
            current.parent()?.join(target)
        };
    }
    None
}

/// The `commondir` of a linked worktree: `<git_dir>/commondir` holds a
/// path (usually `../..`) to the shared directory that owns
/// `info/exclude`. Absent for an ordinary repository.
fn resolve_common_dir(git_dir: &Path) -> PathBuf {
    let Some(bytes) = read_capped(&git_dir.join("commondir"), 64 * 1024) else {
        return git_dir.to_path_buf();
    };
    let text = String::from_utf8_lossy(&bytes);
    let Some(first) = text.lines().next().map(str::trim) else {
        return git_dir.to_path_buf();
    };
    if first.is_empty() {
        return git_dir.to_path_buf();
    }
    let candidate = PathBuf::from(first);
    let joined = if candidate.is_absolute() {
        candidate
    } else {
        git_dir.join(candidate)
    };
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Locate the repository containing `start`, reading only directory
/// entries. Returns `None` when `start` is not inside a work tree.
///
/// `start` should already be canonicalized by the caller; discovery does
/// not canonicalize so that a caller's containment decisions stay stable.
pub fn discover(start: &Path) -> Option<RepoLayout> {
    let mut dir = start;
    for _ in 0..MAX_DISCOVERY_ASCENT {
        let dot_git = dir.join(".git");
        if std::fs::symlink_metadata(&dot_git).is_ok() {
            let git_dir = resolve_git_dir(&dot_git)?;
            let common_dir = resolve_common_dir(&git_dir);
            return Some(RepoLayout {
                work_tree: dir.to_path_buf(),
                git_dir,
                common_dir,
            });
        }
        dir = dir.parent()?;
    }
    None
}

// ---------------------------------------------------------------------------
// `.git/index` (DIRC) parsing
// ---------------------------------------------------------------------------

/// Git's variable-width integer encoding (`varint.c::decode_varint`), used
/// by index version 4 for path prefix compression.
fn decode_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut c = *buf.get(*pos)?;
    *pos += 1;
    let mut val = u64::from(c & 0x7f);
    while c & 0x80 != 0 {
        val = val.checked_add(1)?;
        c = *buf.get(*pos)?;
        *pos += 1;
        val = val.checked_shl(7)?.checked_add(u64::from(c & 0x7f))?;
    }
    Some(val)
}

fn be_u32(buf: &[u8], at: usize) -> Option<u32> {
    let slice = buf.get(at..at + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn be_u16(buf: &[u8], at: usize) -> Option<u16> {
    let slice = buf.get(at..at + 2)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

/// Why an index parse stopped.
#[derive(Debug)]
enum IndexParseError {
    /// The bytes are not a shape this reader understands.
    Unreadable(String),
    /// Rebuilding the paths would have retained more than
    /// [`MAX_INDEX_PATH_BYTES`] (RA-008).
    PathBudget,
}

impl IndexParseError {
    fn unreadable(why: impl Into<String>) -> IndexParseError {
        IndexParseError::Unreadable(why.into())
    }

    fn into_limit(self) -> ViewLimit {
        match self {
            IndexParseError::Unreadable(why) => ViewLimit::IndexUnreadable { why },
            IndexParseError::PathBudget => ViewLimit::IndexPathBudget,
        }
    }
}

/// One parsed `DIRC` file — `.git/index` or `.git/sharedindex.<oid>`.
struct ParsedIndex {
    /// Paths in index order, forward-slash and relative to the work tree.
    ///
    /// A `Vec` rather than a set because a split index addresses shared
    /// entries by POSITION: its delete bitmap says "entry 67 is gone", so
    /// the order has to survive the parse.
    paths: Vec<String>,
    /// The payload of the `link` extension, present only in the main index
    /// of a split-index repository.
    link: Option<Vec<u8>>,
}

/// Attempt a full index parse with a given object-id length.
///
/// `Err` carries a short reason for the caller's warning.
fn parse_index(buf: &[u8], oid_len: usize) -> Result<ParsedIndex, IndexParseError> {
    use IndexParseError as E;
    if buf.len() < 12 {
        return Err(E::unreadable("shorter than a DIRC header"));
    }
    if &buf[0..4] != b"DIRC" {
        return Err(E::unreadable("missing the DIRC signature"));
    }
    let version = be_u32(buf, 4).ok_or_else(|| E::unreadable("truncated version"))?;
    if !matches!(version, 2..=4) {
        return Err(E::unreadable(format!(
            "unsupported index version {version}"
        )));
    }
    let count = be_u32(buf, 8).ok_or_else(|| E::unreadable("truncated entry count"))? as usize;
    // A hostile or corrupt header must not make us allocate: every entry
    // needs at least the fixed part, so the count is bounded by the file.
    let min_entry = 40 + oid_len + 2 + 1;
    if count.saturating_mul(min_entry) > buf.len() {
        return Err(E::unreadable("entry count exceeds the file size"));
    }

    let mut out: Vec<String> = Vec::new();
    let mut pos = 12usize;
    let mut previous: Vec<u8> = Vec::new();
    // Cumulative path text retained so far. Bounding the FILE is not enough
    // for version 4 (RA-008); this is the quantity that actually grows.
    let mut retained = 0usize;

    for _ in 0..count {
        let entry_start = pos;
        // stat data (40) + object id + flags (2)
        let flags_at = pos
            .checked_add(40)
            .and_then(|p| p.checked_add(oid_len))
            .ok_or_else(|| E::unreadable("entry offset overflow"))?;
        let flags = be_u16(buf, flags_at).ok_or_else(|| E::unreadable("truncated entry flags"))?;
        pos = flags_at + 2;
        let extended = flags & 0x4000 != 0;
        if extended {
            if version < 3 {
                return Err(E::unreadable("extended flag set in a version-2 index"));
            }
            // Skip the extra 16-bit flags word.
            if buf.len() < pos + 2 {
                return Err(E::unreadable("truncated extended flags"));
            }
            pos += 2;
        }

        let path: Vec<u8> = if version == 4 {
            let strip = decode_varint(buf, &mut pos)
                .ok_or_else(|| E::unreadable("truncated path varint"))?
                as usize;
            if strip > previous.len() {
                return Err(E::unreadable("prefix strip longer than the previous path"));
            }
            let nul = buf[pos..]
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| E::unreadable("unterminated path"))?;
            let suffix = &buf[pos..pos + nul];
            pos += nul + 1;
            let mut p = previous[..previous.len() - strip].to_vec();
            p.extend_from_slice(suffix);
            p
        } else {
            let nul = buf[pos..]
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| E::unreadable("unterminated path"))?;
            let p = buf[pos..pos + nul].to_vec();
            pos += nul + 1;
            // Versions 2 and 3 pad each entry with NULs to a multiple of
            // eight bytes, measured from the start of the entry.
            let unpadded = pos - entry_start;
            let padded = unpadded.div_ceil(8) * 8;
            pos = entry_start + padded;
            if pos > buf.len() {
                return Err(E::unreadable("padding runs past the end of the index"));
            }
            p
        };

        // Index paths are always forward-slash and relative to the work
        // tree. Non-UTF-8 paths cannot name a `.env*` file we care about,
        // so they are recorded lossily rather than aborting the parse.
        let text = String::from_utf8_lossy(&path).into_owned();
        retained = retained.saturating_add(text.len());
        if retained > MAX_INDEX_PATH_BYTES {
            return Err(E::PathBudget);
        }
        out.push(text);
        // Moved, not cloned: the previous code kept a second copy of every
        // path alive for the duration of the parse.
        previous = path;
    }

    // Walk the tail: what follows the entries is zero or more extensions
    // (4-byte signature, 4-byte big-endian size, payload) and then the
    // trailing checksum. Walking them instead of eyeballing the first four
    // bytes is what makes the object-id-length probe below self-checking,
    // and it is the only way to SEE the `link` extension that marks a split
    // index — which the old check waved through, leaving every file in a
    // split-index repository reported untracked (RA-007).
    let mut link = None;
    loop {
        let remaining = buf.len().saturating_sub(pos);
        if remaining == oid_len {
            break;
        }
        if remaining < oid_len {
            return Err(E::unreadable("no room for the index trailer"));
        }
        let sig = buf
            .get(pos..pos + 4)
            .ok_or_else(|| E::unreadable("truncated extension header"))?;
        if !sig.iter().all(|b| b.is_ascii_alphabetic()) {
            return Err(E::unreadable(
                "unrecognised bytes where an extension header was expected",
            ));
        }
        let is_link = sig == b"link";
        let size =
            be_u32(buf, pos + 4).ok_or_else(|| E::unreadable("truncated extension size"))? as usize;
        let data_at = pos + 8;
        let end = data_at
            .checked_add(size)
            .ok_or_else(|| E::unreadable("extension size overflow"))?;
        if end > buf.len().saturating_sub(oid_len) {
            return Err(E::unreadable("extension runs past the index trailer"));
        }
        if is_link {
            link = Some(buf[data_at..end].to_vec());
        }
        pos = end;
    }
    Ok(ParsedIndex { paths: out, link })
}

/// Decode one EWAH-compressed bitmap from the head of `buf`.
///
/// Git serialises these as `bit_size` (big-endian u32), `word_count`
/// (big-endian u32), `word_count` big-endian 64-bit words, then the
/// running-length-word offset (big-endian u32). A word is either a
/// running-length word — bit 0 the repeated value, bits 1..=32 how many
/// clean 64-bit words it stands for, bits 33..=63 how many literal words
/// follow — or one of those literal words.
///
/// Returns the set positions and how many bytes the bitmap occupied.
/// `max_bit` is the number of entries the bitmap can possibly describe: a
/// run length is a 32-bit word count, so without it a 12-byte payload could
/// ask for 2^38 positions.
fn decode_ewah(buf: &[u8], max_bit: usize) -> Result<(BTreeSet<usize>, usize), String> {
    let bit_size = be_u32(buf, 0).ok_or("truncated EWAH bit size")? as usize;
    let word_count = be_u32(buf, 4).ok_or("truncated EWAH word count")? as usize;
    let total = word_count
        .checked_mul(8)
        .and_then(|b| b.checked_add(12))
        .ok_or("EWAH word count overflows the payload")?;
    if buf.len() < total {
        return Err("EWAH bitmap runs past the extension".into());
    }
    if bit_size > max_bit {
        return Err("EWAH bitmap describes more entries than the index holds".into());
    }
    let word = |i: usize| -> u64 {
        let at = 8 + i * 8;
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[at..at + 8]);
        u64::from_be_bytes(b)
    };

    let mut set = BTreeSet::new();
    let mut bit = 0usize;
    let mut i = 0usize;
    while i < word_count {
        let rlw = word(i);
        i += 1;
        let run_value = rlw & 1 != 0;
        let run_words = ((rlw >> 1) & 0xFFFF_FFFF) as usize;
        let literal_words = (rlw >> 33) as usize;
        let run_bits = run_words.saturating_mul(64);
        if run_value {
            // Clamped by `bit_size`, which `max_bit` already bounds, so a
            // 2^32-word run cannot make this loop unbounded.
            for b in bit..bit.saturating_add(run_bits).min(bit_size) {
                set.insert(b);
            }
        }
        bit = bit.saturating_add(run_bits);
        for _ in 0..literal_words {
            if i >= word_count {
                return Err("EWAH literal words run past the buffer".into());
            }
            let literal = word(i);
            i += 1;
            for b in 0..64 {
                if literal >> b & 1 != 0 && bit.saturating_add(b) < bit_size {
                    set.insert(bit + b);
                }
            }
            bit = bit.saturating_add(64);
        }
    }
    Ok((set, total))
}

/// Resolve a split index into the set of tracked paths.
///
/// In split-index mode `.git/index` holds one name-less placeholder per
/// shared entry it replaces (plus real entries for anything newly added),
/// and the `link` extension names `.git/sharedindex.<oid>` where the actual
/// paths live, followed by two EWAH bitmaps over the shared entries: a
/// delete bitmap and a replace bitmap.
///
/// Only the delete bitmap changes the answer. A replacement carries the
/// base entry's name (git refuses to read one with a name of its own), so
/// it can never introduce or remove a path — the replace bitmap is decoded
/// solely to prove the extension is intact.
fn resolve_split_index(
    git_dir: &Path,
    main_paths: Vec<String>,
    link: &[u8],
    oid_len: usize,
) -> Result<BTreeSet<String>, ViewLimit> {
    let unreadable = |why: &str| ViewLimit::IndexUnreadable {
        why: format!("split index: {why}"),
    };
    let oid = link
        .get(..oid_len)
        .ok_or_else(|| unreadable("the link extension is shorter than an object id"))?;
    // "If all bits are zero, the index does not require a shared index file
    // anymore" — the entries in the main index are then the whole truth.
    if oid.iter().all(|b| *b == 0) {
        return Ok(main_paths.into_iter().filter(|p| !p.is_empty()).collect());
    }
    let mut name = String::with_capacity(13 + oid_len * 2);
    name.push_str("sharedindex.");
    for byte in oid {
        name.push_str(&format!("{byte:02x}"));
    }
    let shared_path = git_dir.join(&name);

    let meta = std::fs::symlink_metadata(&shared_path)
        .map_err(|e| unreadable(&format!("{name} could not be opened ({e})")))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(unreadable(&format!("{name} is not a regular file")));
    }
    if meta.len() > MAX_INDEX_BYTES {
        return Err(ViewLimit::IndexTooLarge { bytes: meta.len() });
    }
    let shared_buf =
        std::fs::read(&shared_path).map_err(|e| unreadable(&format!("{name} ({e})")))?;
    let shared = parse_index(&shared_buf, oid_len).map_err(|e| match e.into_limit() {
        ViewLimit::IndexUnreadable { why } => unreadable(&why),
        other => other,
    })?;
    if shared.link.is_some() {
        // Git never chains shared indexes; a file that claims to would let
        // a repository point this reader at an unbounded chain.
        return Err(unreadable(
            "the shared index carries a link extension of its own",
        ));
    }

    // Git's writer emits the object id and then STOPS when it holds neither
    // bitmap (`write_link_extension`), so a payload that is exactly an
    // object id means "nothing deleted, nothing replaced" — not a truncated
    // extension. Rejecting it would degrade a perfectly readable repository
    // to `Unknown`.
    let bitmaps = &link[oid_len..];
    let deleted = if bitmaps.is_empty() {
        BTreeSet::new()
    } else {
        let (deleted, delete_len) =
            decode_ewah(bitmaps, shared.paths.len()).map_err(|e| unreadable(&e))?;
        let (_replaced, replace_len) = decode_ewah(
            bitmaps
                .get(delete_len..)
                .ok_or_else(|| unreadable("the replace bitmap is missing"))?,
            shared.paths.len(),
        )
        .map_err(|e| unreadable(&e))?;
        if delete_len + replace_len != bitmaps.len() {
            return Err(unreadable("trailing bytes after the two bitmaps"));
        }
        deleted
    };

    let mut tracked: BTreeSet<String> = BTreeSet::new();
    for (position, path) in shared.paths.into_iter().enumerate() {
        if !path.is_empty() && !deleted.contains(&position) {
            tracked.insert(path);
        }
    }
    // Anything the main index names outright was added since the shared
    // index was written.
    tracked.extend(main_paths.into_iter().filter(|p| !p.is_empty()));
    Ok(tracked)
}

/// Every path in `.git/index`, or a reason it could not be read.
///
/// The object-id length (20 for SHA-1, 32 for SHA-256) is not recorded in
/// the index header, so both are attempted; the tail walk inside
/// [`parse_index`] rejects the wrong one.
pub fn read_index(git_dir: &Path) -> Result<BTreeSet<String>, ViewLimit> {
    let path = git_dir.join("index");
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        // No index at all (a freshly `git init`ed repository): nothing is
        // tracked, which is a complete and correct answer. Any OTHER error
        // is not — an unreadable `.git` used to return the same empty set,
        // which reads as "no secret is committed here" and disables the
        // product's only committed-secret control (RA-007).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(e) => return Err(ViewLimit::IndexUnreadable { why: e.to_string() }),
    };
    if meta.file_type().is_symlink() {
        // Same rule as `read_capped`: never read through a symlink at the
        // final component. Refuse honestly instead of claiming nothing is
        // tracked (RA-007).
        return Err(ViewLimit::IndexUnreadable {
            why: "`.git/index` is a symlink".into(),
        });
    }
    if !meta.is_file() {
        return Err(ViewLimit::IndexUnreadable {
            why: "`.git/index` is not a regular file".into(),
        });
    }
    if meta.len() > MAX_INDEX_BYTES {
        return Err(ViewLimit::IndexTooLarge { bytes: meta.len() });
    }
    let buf =
        std::fs::read(&path).map_err(|e| ViewLimit::IndexUnreadable { why: e.to_string() })?;
    let (parsed, oid_len) = match parse_index(&buf, 20) {
        Ok(parsed) => (parsed, 20),
        Err(sha1) => match parse_index(&buf, 32) {
            Ok(parsed) => (parsed, 32),
            Err(_) => return Err(sha1.into_limit()),
        },
    };
    match parsed.link {
        // An empty name is a split-index placeholder and cannot name a
        // file; dropping it here also keeps a corrupt entry out of the set.
        None => Ok(parsed.paths.into_iter().filter(|p| !p.is_empty()).collect()),
        Some(link) => resolve_split_index(git_dir, parsed.paths, &link, oid_len),
    }
}

// ---------------------------------------------------------------------------
// `.gitignore` evaluation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct IgnorePattern {
    /// Directory (repo-relative, no leading or trailing slash) the pattern
    /// was declared in. Empty for the work-tree root.
    base: String,
    /// The pattern with `!`, anchoring slash and trailing slash removed.
    body: String,
    negated: bool,
    dir_only: bool,
    /// The pattern contained a non-trailing `/`, so it is anchored to
    /// `base` instead of matching any basename below it.
    anchored: bool,
}

/// Repository-local ignore rules, ordered by increasing precedence.
#[derive(Debug, Clone, Default)]
pub struct IgnoreRules {
    patterns: Vec<IgnorePattern>,
    limits: Vec<ViewLimit>,
}

/// Strip trailing unescaped whitespace, the way Git does.
fn trim_trailing_unescaped_spaces(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        // A backslash immediately before the run makes the space literal.
        let mut backslashes = 0usize;
        let mut i = end - 1;
        while i > 0 && bytes[i - 1] == b'\\' {
            backslashes += 1;
            i -= 1;
        }
        if backslashes % 2 == 1 {
            break;
        }
        end -= 1;
    }
    &s[..end]
}

fn parse_ignore_file(base: &str, content: &str, out: &mut Vec<IgnorePattern>) -> bool {
    for raw in content.lines() {
        if out.len() >= MAX_IGNORE_PATTERNS {
            return false;
        }
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let line = trim_trailing_unescaped_spaces(line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let (negated, rest) = match line.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, line.strip_prefix("\\!").unwrap_or(line)),
        };
        if rest.is_empty() {
            continue;
        }
        let dir_only = rest.ends_with('/');
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty() {
            continue;
        }
        // Anchored when a slash appears anywhere except as the (already
        // removed) trailing one.
        let anchored = rest.contains('/');
        let body = rest.strip_prefix('/').unwrap_or(rest).to_string();
        if body.is_empty() {
            continue;
        }
        out.push(IgnorePattern {
            base: base.to_string(),
            body,
            negated,
            dir_only,
            anchored,
        });
    }
    true
}

/// Match one path component against a glob component. `*` and `?` never
/// cross a `/`, which is why matching is done per component.
fn glob_match_segment(pattern: &[char], text: &[char]) -> bool {
    // Iterative backtracking: linear in the common case, no recursion, so
    // a hostile pattern cannot blow the stack.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (usize::MAX, 0usize);
    while t < text.len() {
        if p < pattern.len() {
            match pattern[p] {
                '*' => {
                    star_p = p;
                    star_t = t;
                    p += 1;
                    continue;
                }
                '?' => {
                    p += 1;
                    t += 1;
                    continue;
                }
                '[' => {
                    if let Some((matched, next_p)) = match_class(pattern, p, text[t]) {
                        if matched {
                            p = next_p;
                            t += 1;
                            continue;
                        }
                    } else if pattern[p] == text[t] {
                        // Unterminated '[' is a literal bracket.
                        p += 1;
                        t += 1;
                        continue;
                    }
                }
                '\\' if p + 1 < pattern.len() => {
                    if pattern[p + 1] == text[t] {
                        p += 2;
                        t += 1;
                        continue;
                    }
                }
                c if c == text[t] => {
                    p += 1;
                    t += 1;
                    continue;
                }
                _ => {}
            }
        }
        if star_p != usize::MAX {
            star_t += 1;
            t = star_t;
            p = star_p + 1;
            continue;
        }
        return false;
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Evaluate a `[...]` character class starting at `pattern[at]`.
/// Returns `(matched, index just past the class)`, or `None` when the
/// class is unterminated.
fn match_class(pattern: &[char], at: usize, c: char) -> Option<(bool, usize)> {
    let mut i = at + 1;
    let negate = matches!(pattern.get(i), Some('!') | Some('^'));
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let ch = *pattern.get(i)?;
        if ch == ']' && !first {
            i += 1;
            break;
        }
        first = false;
        // `[a-z]`
        if pattern.get(i + 1) == Some(&'-') && pattern.get(i + 2).is_some_and(|n| *n != ']') {
            let lo = ch;
            let hi = pattern[i + 2];
            if c >= lo && c <= hi {
                matched = true;
            }
            i += 3;
            continue;
        }
        if ch == c {
            matched = true;
        }
        i += 1;
    }
    Some((matched != negate, i))
}

/// Match a `/`-separated pattern (which may contain `**`) against a
/// `/`-separated path, both already split into components.
fn glob_match_path(pattern: &[&str], text: &[&str]) -> bool {
    // `**` matches zero or more components; everything else matches one.
    //
    // This used to recurse over `0..=text.len()` for every `**`, with no
    // memoisation and no budget, so a pattern's cost grew by about 7x per
    // added `**`: the auditor measured 2.5s at ten of them and 18.3s at
    // twelve, multiplied again by the ancestor loop, the unanchored
    // start-offset loop, and up to MAX_IGNORE_PATTERNS rules — and the
    // discovery time budget could not preempt a single call (RA-009).
    //
    // The same greedy backtracking `glob_match_segment` uses for `*` solves
    // this exactly: `**` is a wildcard over COMPONENTS, so remembering only
    // the most recent one and resuming it one component later is both
    // correct and O(pattern x text). No recursion, so no stack growth
    // either.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (usize::MAX, 0usize);
    while t < text.len() {
        if p < pattern.len() {
            if pattern[p] == "**" {
                star_p = p;
                star_t = t;
                p += 1;
                continue;
            }
            let seg: Vec<char> = pattern[p].chars().collect();
            let component: Vec<char> = text[t].chars().collect();
            if glob_match_segment(&seg, &component) {
                p += 1;
                t += 1;
                continue;
            }
        }
        if star_p != usize::MAX {
            star_t += 1;
            t = star_t;
            p = star_p + 1;
            continue;
        }
        return false;
    }
    while p < pattern.len() && pattern[p] == "**" {
        p += 1;
    }
    p == pattern.len()
}

impl IgnoreRules {
    /// Whether `rel` (repo-relative, forward slashes, no leading slash) is
    /// ignored. `is_dir` selects whether directory-only patterns apply.
    ///
    /// Git's precedence is applied: rules from deeper directories override
    /// shallower ones, and within one file the last matching rule wins.
    /// A file inside an excluded directory stays excluded even if a later
    /// rule would re-include the file itself, matching Git's documented
    /// behaviour.
    pub fn is_ignored(&self, rel: &str, is_dir: bool) -> bool {
        // Test each ancestor directory first: once a directory is
        // excluded, Git does not descend into it.
        let components: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
        for depth in 1..components.len() {
            let ancestor = components[..depth].join("/");
            if self.matches(&ancestor, true) {
                return true;
            }
        }
        self.matches(rel, is_dir)
    }

    fn matches(&self, rel: &str, is_dir: bool) -> bool {
        let mut decision = false;
        // Patterns are stored shallow-base-first, and within a base in
        // file order, so a straight scan already yields "last match wins"
        // with deeper files overriding shallower ones.
        for pattern in &self.patterns {
            if pattern.dir_only && !is_dir {
                continue;
            }
            let Some(under) = strip_base(rel, &pattern.base) else {
                continue;
            };
            let path_parts: Vec<&str> = under.split('/').filter(|c| !c.is_empty()).collect();
            if path_parts.is_empty() {
                continue;
            }
            let pat_parts: Vec<&str> = pattern.body.split('/').collect();
            let hit = if pattern.anchored {
                glob_match_path(&pat_parts, &path_parts)
            } else {
                // Unanchored: match the pattern against the basename, or
                // against any trailing run of components for `**`-style
                // bodies.
                let mut any = false;
                for start in 0..path_parts.len() {
                    if glob_match_path(&pat_parts, &path_parts[start..]) {
                        any = true;
                        break;
                    }
                }
                any
            };
            if hit {
                decision = !pattern.negated;
            }
        }
        decision
    }

    /// Bounds that were hit while loading, for honest scan warnings.
    pub fn limits(&self) -> &[ViewLimit] {
        &self.limits
    }
}

/// `rel` relative to `base`, or `None` when `rel` is not under `base`.
fn strip_base<'a>(rel: &'a str, base: &str) -> Option<&'a str> {
    if base.is_empty() {
        return Some(rel);
    }
    let with_slash = rel.strip_prefix(base)?;
    with_slash.strip_prefix('/')
}

/// Load `.git/info/exclude` plus every `.gitignore` from the work-tree
/// root down to `dir_rel`, in Git's precedence order.
pub fn load_ignore_rules(layout: &RepoLayout, dir_rel: &str) -> IgnoreRules {
    let mut patterns = Vec::new();
    let mut limits = Vec::new();
    let mut budget_ok = true;

    let mut load = |base: &str, path: PathBuf, patterns: &mut Vec<IgnorePattern>| {
        if !budget_ok {
            return;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && meta.len() > MAX_IGNORE_BYTES => {
                limits.push(ViewLimit::IgnoreFileTooLarge {
                    path: path.display().to_string(),
                });
                return;
            }
            Ok(meta) if meta.is_file() => {}
            _ => return,
        }
        let Some(bytes) = read_capped(&path, MAX_IGNORE_BYTES) else {
            return;
        };
        let content = String::from_utf8_lossy(&bytes);
        if !parse_ignore_file(base, &content, patterns) {
            budget_ok = false;
            limits.push(ViewLimit::IgnorePatternBudget);
        }
    };

    // Lowest precedence: the repository's own exclude file.
    load(
        "",
        layout.common_dir.join("info").join("exclude"),
        &mut patterns,
    );
    // Then `.gitignore` from the root down; deeper files come later and so
    // win under "last match wins".
    load("", layout.work_tree.join(".gitignore"), &mut patterns);
    let mut prefix = String::new();
    for component in dir_rel.split('/').filter(|c| !c.is_empty()) {
        if prefix.is_empty() {
            prefix = component.to_string();
        } else {
            prefix.push('/');
            prefix.push_str(component);
        }
        let dir = layout
            .work_tree
            .join(prefix.replace('/', std::path::MAIN_SEPARATOR_STR));
        load(&prefix.clone(), dir.join(".gitignore"), &mut patterns);
    }

    IgnoreRules { patterns, limits }
}

// ---------------------------------------------------------------------------
// Unicode normalisation for path comparison
// ---------------------------------------------------------------------------

// Git's index stores the precomposed (NFC) form of a path — on macOS
// `core.precomposeunicode` has defaulted to true since Git 1.8.5 — while
// `readdir` on an APFS or HFS+ volume hands back the decomposed (NFD) form.
// The two are the same file name and different bytes, so the exact-bytes
// lookup that decides `Tracked` missed a COMMITTED `.env` whose directory
// name carried an accent and reported it `Untracked` (RA-018).
//
// The comparison below folds both sides to their canonical decomposition.
// It is deliberately not a general NFD implementation: no dependency was
// added for it (nothing in the workspace provides normalisation), it covers
// the scripts that appear in directory names rather than all of Unicode,
// and it does not reorder combining marks, because both inputs are already
// in a normal form and normalisation never emits marks out of canonical
// order. What it is NOT allowed to do is collapse distinct names together —
// so it decomposes rather than stripping accents, and `resume` and `résumé`
// stay different paths.
//
// The fold is applied on every platform, not behind `cfg(target_os =
// "macos")`: a work tree checked out on macOS and read on Linux carries the
// same mismatch, and a macOS-only code path is a code path only macOS CI
// ever executes.

/// Hangul syllables decompose by arithmetic (Unicode 3.12), so 11 172 of
/// them need no table at all.
const HANGUL_S_BASE: u32 = 0xAC00;
const HANGUL_L_BASE: u32 = 0x1100;
const HANGUL_V_BASE: u32 = 0x1161;
const HANGUL_T_BASE: u32 = 0x11A7;
const HANGUL_T_COUNT: u32 = 28;
const HANGUL_N_COUNT: u32 = 21 * HANGUL_T_COUNT;
const HANGUL_S_COUNT: u32 = 19 * HANGUL_N_COUNT;

/// How many times a decomposition may be re-expanded. Canonical
/// decompositions in the table above chain at most twice (U+1EC7 to
/// U+1EB9 + U+0302, then U+1EB9 to U+0065 + U+0323); the guard exists so a
/// mistaken table edit cannot recurse without bound.
const MAX_DECOMPOSITION_DEPTH: usize = 4;

fn push_decomposed(c: char, depth: usize, out: &mut String) {
    let cp = c as u32;
    if depth == 0 {
        out.push(c);
        return;
    }
    if let Some(index) = cp
        .checked_sub(HANGUL_S_BASE)
        .filter(|i| *i < HANGUL_S_COUNT)
    {
        let lead = char::from_u32(HANGUL_L_BASE + index / HANGUL_N_COUNT);
        let vowel = char::from_u32(HANGUL_V_BASE + (index % HANGUL_N_COUNT) / HANGUL_T_COUNT);
        if let (Some(lead), Some(vowel)) = (lead, vowel) {
            out.push(lead);
            out.push(vowel);
            let trail = index % HANGUL_T_COUNT;
            if trail > 0 {
                if let Some(trail) = char::from_u32(HANGUL_T_BASE + trail) {
                    out.push(trail);
                }
            }
            return;
        }
    }
    if let Ok(cp) = u16::try_from(cp) {
        if let Ok(at) =
            CANONICAL_DECOMPOSITION.binary_search_by_key(&cp, |(composed, _, _)| *composed)
        {
            let (_, base, mark) = CANONICAL_DECOMPOSITION[at];
            if let Some(base) = char::from_u32(u32::from(base)) {
                push_decomposed(base, depth - 1, out);
                if let Some(mark) = char::from_u32(u32::from(mark)).filter(|_| mark != 0) {
                    out.push(mark);
                }
                return;
            }
        }
    }
    out.push(c);
}

/// `s` with every precomposed character the table covers replaced by its
/// canonical decomposition. ASCII is returned unchanged.
fn canonical_decomposition(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        push_decomposed(c, MAX_DECOMPOSITION_DEPTH, &mut out);
    }
    out
}

/// Canonical decompositions of the precomposed Latin, Greek and Cyrillic
/// letters, as `(composed, base, mark)` sorted by `composed`. `mark` is
/// `0x0000` for the six singleton decompositions in range (U+0340 to
/// U+0300, U+037E to U+003B, and so on).
///
/// Generated from Python 3's `unicodedata` (Unicode 16.0.0) over
/// U+00C0..U+04FF and U+1E00..U+1EFF — where the accented letters,
/// Vietnamese tone marks and Cyrillic breves that occur in real directory
/// names live. Scripts outside those ranges (polytonic Greek, the CJK
/// compatibility ideographs, the Indic and Arabic precomposed forms) are
/// deliberately not covered: a path using them still compares by exact
/// bytes, exactly as it did before.
///
/// Regenerate with:
///
/// ```text
/// python3 -c 'import unicodedata
/// for cp in list(range(0xC0,0x500)) + list(range(0x1E00,0x1F00)):
///     d = unicodedata.decomposition(chr(cp))
///     if not d or d.startswith("<"): continue
///     p = [int(x, 16) for x in d.split()]
///     print("(0x%04X, 0x%04X, 0x%04X)," % (cp, p[0], p[1] if len(p) > 1 else 0))'
/// ```
///
/// `decomposition_table_is_well_formed` below pins its invariants and
/// spot-checks it against hand-verified values, so a stray edit cannot
/// silently break the lookup that depends on it.
const CANONICAL_DECOMPOSITION: &[(u16, u16, u16)] = &[
    (0x00C0, 0x0041, 0x0300),
    (0x00C1, 0x0041, 0x0301),
    (0x00C2, 0x0041, 0x0302),
    (0x00C3, 0x0041, 0x0303),
    (0x00C4, 0x0041, 0x0308),
    (0x00C5, 0x0041, 0x030A),
    (0x00C7, 0x0043, 0x0327),
    (0x00C8, 0x0045, 0x0300),
    (0x00C9, 0x0045, 0x0301),
    (0x00CA, 0x0045, 0x0302),
    (0x00CB, 0x0045, 0x0308),
    (0x00CC, 0x0049, 0x0300),
    (0x00CD, 0x0049, 0x0301),
    (0x00CE, 0x0049, 0x0302),
    (0x00CF, 0x0049, 0x0308),
    (0x00D1, 0x004E, 0x0303),
    (0x00D2, 0x004F, 0x0300),
    (0x00D3, 0x004F, 0x0301),
    (0x00D4, 0x004F, 0x0302),
    (0x00D5, 0x004F, 0x0303),
    (0x00D6, 0x004F, 0x0308),
    (0x00D9, 0x0055, 0x0300),
    (0x00DA, 0x0055, 0x0301),
    (0x00DB, 0x0055, 0x0302),
    (0x00DC, 0x0055, 0x0308),
    (0x00DD, 0x0059, 0x0301),
    (0x00E0, 0x0061, 0x0300),
    (0x00E1, 0x0061, 0x0301),
    (0x00E2, 0x0061, 0x0302),
    (0x00E3, 0x0061, 0x0303),
    (0x00E4, 0x0061, 0x0308),
    (0x00E5, 0x0061, 0x030A),
    (0x00E7, 0x0063, 0x0327),
    (0x00E8, 0x0065, 0x0300),
    (0x00E9, 0x0065, 0x0301),
    (0x00EA, 0x0065, 0x0302),
    (0x00EB, 0x0065, 0x0308),
    (0x00EC, 0x0069, 0x0300),
    (0x00ED, 0x0069, 0x0301),
    (0x00EE, 0x0069, 0x0302),
    (0x00EF, 0x0069, 0x0308),
    (0x00F1, 0x006E, 0x0303),
    (0x00F2, 0x006F, 0x0300),
    (0x00F3, 0x006F, 0x0301),
    (0x00F4, 0x006F, 0x0302),
    (0x00F5, 0x006F, 0x0303),
    (0x00F6, 0x006F, 0x0308),
    (0x00F9, 0x0075, 0x0300),
    (0x00FA, 0x0075, 0x0301),
    (0x00FB, 0x0075, 0x0302),
    (0x00FC, 0x0075, 0x0308),
    (0x00FD, 0x0079, 0x0301),
    (0x00FF, 0x0079, 0x0308),
    (0x0100, 0x0041, 0x0304),
    (0x0101, 0x0061, 0x0304),
    (0x0102, 0x0041, 0x0306),
    (0x0103, 0x0061, 0x0306),
    (0x0104, 0x0041, 0x0328),
    (0x0105, 0x0061, 0x0328),
    (0x0106, 0x0043, 0x0301),
    (0x0107, 0x0063, 0x0301),
    (0x0108, 0x0043, 0x0302),
    (0x0109, 0x0063, 0x0302),
    (0x010A, 0x0043, 0x0307),
    (0x010B, 0x0063, 0x0307),
    (0x010C, 0x0043, 0x030C),
    (0x010D, 0x0063, 0x030C),
    (0x010E, 0x0044, 0x030C),
    (0x010F, 0x0064, 0x030C),
    (0x0112, 0x0045, 0x0304),
    (0x0113, 0x0065, 0x0304),
    (0x0114, 0x0045, 0x0306),
    (0x0115, 0x0065, 0x0306),
    (0x0116, 0x0045, 0x0307),
    (0x0117, 0x0065, 0x0307),
    (0x0118, 0x0045, 0x0328),
    (0x0119, 0x0065, 0x0328),
    (0x011A, 0x0045, 0x030C),
    (0x011B, 0x0065, 0x030C),
    (0x011C, 0x0047, 0x0302),
    (0x011D, 0x0067, 0x0302),
    (0x011E, 0x0047, 0x0306),
    (0x011F, 0x0067, 0x0306),
    (0x0120, 0x0047, 0x0307),
    (0x0121, 0x0067, 0x0307),
    (0x0122, 0x0047, 0x0327),
    (0x0123, 0x0067, 0x0327),
    (0x0124, 0x0048, 0x0302),
    (0x0125, 0x0068, 0x0302),
    (0x0128, 0x0049, 0x0303),
    (0x0129, 0x0069, 0x0303),
    (0x012A, 0x0049, 0x0304),
    (0x012B, 0x0069, 0x0304),
    (0x012C, 0x0049, 0x0306),
    (0x012D, 0x0069, 0x0306),
    (0x012E, 0x0049, 0x0328),
    (0x012F, 0x0069, 0x0328),
    (0x0130, 0x0049, 0x0307),
    (0x0134, 0x004A, 0x0302),
    (0x0135, 0x006A, 0x0302),
    (0x0136, 0x004B, 0x0327),
    (0x0137, 0x006B, 0x0327),
    (0x0139, 0x004C, 0x0301),
    (0x013A, 0x006C, 0x0301),
    (0x013B, 0x004C, 0x0327),
    (0x013C, 0x006C, 0x0327),
    (0x013D, 0x004C, 0x030C),
    (0x013E, 0x006C, 0x030C),
    (0x0143, 0x004E, 0x0301),
    (0x0144, 0x006E, 0x0301),
    (0x0145, 0x004E, 0x0327),
    (0x0146, 0x006E, 0x0327),
    (0x0147, 0x004E, 0x030C),
    (0x0148, 0x006E, 0x030C),
    (0x014C, 0x004F, 0x0304),
    (0x014D, 0x006F, 0x0304),
    (0x014E, 0x004F, 0x0306),
    (0x014F, 0x006F, 0x0306),
    (0x0150, 0x004F, 0x030B),
    (0x0151, 0x006F, 0x030B),
    (0x0154, 0x0052, 0x0301),
    (0x0155, 0x0072, 0x0301),
    (0x0156, 0x0052, 0x0327),
    (0x0157, 0x0072, 0x0327),
    (0x0158, 0x0052, 0x030C),
    (0x0159, 0x0072, 0x030C),
    (0x015A, 0x0053, 0x0301),
    (0x015B, 0x0073, 0x0301),
    (0x015C, 0x0053, 0x0302),
    (0x015D, 0x0073, 0x0302),
    (0x015E, 0x0053, 0x0327),
    (0x015F, 0x0073, 0x0327),
    (0x0160, 0x0053, 0x030C),
    (0x0161, 0x0073, 0x030C),
    (0x0162, 0x0054, 0x0327),
    (0x0163, 0x0074, 0x0327),
    (0x0164, 0x0054, 0x030C),
    (0x0165, 0x0074, 0x030C),
    (0x0168, 0x0055, 0x0303),
    (0x0169, 0x0075, 0x0303),
    (0x016A, 0x0055, 0x0304),
    (0x016B, 0x0075, 0x0304),
    (0x016C, 0x0055, 0x0306),
    (0x016D, 0x0075, 0x0306),
    (0x016E, 0x0055, 0x030A),
    (0x016F, 0x0075, 0x030A),
    (0x0170, 0x0055, 0x030B),
    (0x0171, 0x0075, 0x030B),
    (0x0172, 0x0055, 0x0328),
    (0x0173, 0x0075, 0x0328),
    (0x0174, 0x0057, 0x0302),
    (0x0175, 0x0077, 0x0302),
    (0x0176, 0x0059, 0x0302),
    (0x0177, 0x0079, 0x0302),
    (0x0178, 0x0059, 0x0308),
    (0x0179, 0x005A, 0x0301),
    (0x017A, 0x007A, 0x0301),
    (0x017B, 0x005A, 0x0307),
    (0x017C, 0x007A, 0x0307),
    (0x017D, 0x005A, 0x030C),
    (0x017E, 0x007A, 0x030C),
    (0x01A0, 0x004F, 0x031B),
    (0x01A1, 0x006F, 0x031B),
    (0x01AF, 0x0055, 0x031B),
    (0x01B0, 0x0075, 0x031B),
    (0x01CD, 0x0041, 0x030C),
    (0x01CE, 0x0061, 0x030C),
    (0x01CF, 0x0049, 0x030C),
    (0x01D0, 0x0069, 0x030C),
    (0x01D1, 0x004F, 0x030C),
    (0x01D2, 0x006F, 0x030C),
    (0x01D3, 0x0055, 0x030C),
    (0x01D4, 0x0075, 0x030C),
    (0x01D5, 0x00DC, 0x0304),
    (0x01D6, 0x00FC, 0x0304),
    (0x01D7, 0x00DC, 0x0301),
    (0x01D8, 0x00FC, 0x0301),
    (0x01D9, 0x00DC, 0x030C),
    (0x01DA, 0x00FC, 0x030C),
    (0x01DB, 0x00DC, 0x0300),
    (0x01DC, 0x00FC, 0x0300),
    (0x01DE, 0x00C4, 0x0304),
    (0x01DF, 0x00E4, 0x0304),
    (0x01E0, 0x0226, 0x0304),
    (0x01E1, 0x0227, 0x0304),
    (0x01E2, 0x00C6, 0x0304),
    (0x01E3, 0x00E6, 0x0304),
    (0x01E6, 0x0047, 0x030C),
    (0x01E7, 0x0067, 0x030C),
    (0x01E8, 0x004B, 0x030C),
    (0x01E9, 0x006B, 0x030C),
    (0x01EA, 0x004F, 0x0328),
    (0x01EB, 0x006F, 0x0328),
    (0x01EC, 0x01EA, 0x0304),
    (0x01ED, 0x01EB, 0x0304),
    (0x01EE, 0x01B7, 0x030C),
    (0x01EF, 0x0292, 0x030C),
    (0x01F0, 0x006A, 0x030C),
    (0x01F4, 0x0047, 0x0301),
    (0x01F5, 0x0067, 0x0301),
    (0x01F8, 0x004E, 0x0300),
    (0x01F9, 0x006E, 0x0300),
    (0x01FA, 0x00C5, 0x0301),
    (0x01FB, 0x00E5, 0x0301),
    (0x01FC, 0x00C6, 0x0301),
    (0x01FD, 0x00E6, 0x0301),
    (0x01FE, 0x00D8, 0x0301),
    (0x01FF, 0x00F8, 0x0301),
    (0x0200, 0x0041, 0x030F),
    (0x0201, 0x0061, 0x030F),
    (0x0202, 0x0041, 0x0311),
    (0x0203, 0x0061, 0x0311),
    (0x0204, 0x0045, 0x030F),
    (0x0205, 0x0065, 0x030F),
    (0x0206, 0x0045, 0x0311),
    (0x0207, 0x0065, 0x0311),
    (0x0208, 0x0049, 0x030F),
    (0x0209, 0x0069, 0x030F),
    (0x020A, 0x0049, 0x0311),
    (0x020B, 0x0069, 0x0311),
    (0x020C, 0x004F, 0x030F),
    (0x020D, 0x006F, 0x030F),
    (0x020E, 0x004F, 0x0311),
    (0x020F, 0x006F, 0x0311),
    (0x0210, 0x0052, 0x030F),
    (0x0211, 0x0072, 0x030F),
    (0x0212, 0x0052, 0x0311),
    (0x0213, 0x0072, 0x0311),
    (0x0214, 0x0055, 0x030F),
    (0x0215, 0x0075, 0x030F),
    (0x0216, 0x0055, 0x0311),
    (0x0217, 0x0075, 0x0311),
    (0x0218, 0x0053, 0x0326),
    (0x0219, 0x0073, 0x0326),
    (0x021A, 0x0054, 0x0326),
    (0x021B, 0x0074, 0x0326),
    (0x021E, 0x0048, 0x030C),
    (0x021F, 0x0068, 0x030C),
    (0x0226, 0x0041, 0x0307),
    (0x0227, 0x0061, 0x0307),
    (0x0228, 0x0045, 0x0327),
    (0x0229, 0x0065, 0x0327),
    (0x022A, 0x00D6, 0x0304),
    (0x022B, 0x00F6, 0x0304),
    (0x022C, 0x00D5, 0x0304),
    (0x022D, 0x00F5, 0x0304),
    (0x022E, 0x004F, 0x0307),
    (0x022F, 0x006F, 0x0307),
    (0x0230, 0x022E, 0x0304),
    (0x0231, 0x022F, 0x0304),
    (0x0232, 0x0059, 0x0304),
    (0x0233, 0x0079, 0x0304),
    (0x0340, 0x0300, 0x0000),
    (0x0341, 0x0301, 0x0000),
    (0x0343, 0x0313, 0x0000),
    (0x0344, 0x0308, 0x0301),
    (0x0374, 0x02B9, 0x0000),
    (0x037E, 0x003B, 0x0000),
    (0x0385, 0x00A8, 0x0301),
    (0x0386, 0x0391, 0x0301),
    (0x0387, 0x00B7, 0x0000),
    (0x0388, 0x0395, 0x0301),
    (0x0389, 0x0397, 0x0301),
    (0x038A, 0x0399, 0x0301),
    (0x038C, 0x039F, 0x0301),
    (0x038E, 0x03A5, 0x0301),
    (0x038F, 0x03A9, 0x0301),
    (0x0390, 0x03CA, 0x0301),
    (0x03AA, 0x0399, 0x0308),
    (0x03AB, 0x03A5, 0x0308),
    (0x03AC, 0x03B1, 0x0301),
    (0x03AD, 0x03B5, 0x0301),
    (0x03AE, 0x03B7, 0x0301),
    (0x03AF, 0x03B9, 0x0301),
    (0x03B0, 0x03CB, 0x0301),
    (0x03CA, 0x03B9, 0x0308),
    (0x03CB, 0x03C5, 0x0308),
    (0x03CC, 0x03BF, 0x0301),
    (0x03CD, 0x03C5, 0x0301),
    (0x03CE, 0x03C9, 0x0301),
    (0x03D3, 0x03D2, 0x0301),
    (0x03D4, 0x03D2, 0x0308),
    (0x0400, 0x0415, 0x0300),
    (0x0401, 0x0415, 0x0308),
    (0x0403, 0x0413, 0x0301),
    (0x0407, 0x0406, 0x0308),
    (0x040C, 0x041A, 0x0301),
    (0x040D, 0x0418, 0x0300),
    (0x040E, 0x0423, 0x0306),
    (0x0419, 0x0418, 0x0306),
    (0x0439, 0x0438, 0x0306),
    (0x0450, 0x0435, 0x0300),
    (0x0451, 0x0435, 0x0308),
    (0x0453, 0x0433, 0x0301),
    (0x0457, 0x0456, 0x0308),
    (0x045C, 0x043A, 0x0301),
    (0x045D, 0x0438, 0x0300),
    (0x045E, 0x0443, 0x0306),
    (0x0476, 0x0474, 0x030F),
    (0x0477, 0x0475, 0x030F),
    (0x04C1, 0x0416, 0x0306),
    (0x04C2, 0x0436, 0x0306),
    (0x04D0, 0x0410, 0x0306),
    (0x04D1, 0x0430, 0x0306),
    (0x04D2, 0x0410, 0x0308),
    (0x04D3, 0x0430, 0x0308),
    (0x04D6, 0x0415, 0x0306),
    (0x04D7, 0x0435, 0x0306),
    (0x04DA, 0x04D8, 0x0308),
    (0x04DB, 0x04D9, 0x0308),
    (0x04DC, 0x0416, 0x0308),
    (0x04DD, 0x0436, 0x0308),
    (0x04DE, 0x0417, 0x0308),
    (0x04DF, 0x0437, 0x0308),
    (0x04E2, 0x0418, 0x0304),
    (0x04E3, 0x0438, 0x0304),
    (0x04E4, 0x0418, 0x0308),
    (0x04E5, 0x0438, 0x0308),
    (0x04E6, 0x041E, 0x0308),
    (0x04E7, 0x043E, 0x0308),
    (0x04EA, 0x04E8, 0x0308),
    (0x04EB, 0x04E9, 0x0308),
    (0x04EC, 0x042D, 0x0308),
    (0x04ED, 0x044D, 0x0308),
    (0x04EE, 0x0423, 0x0304),
    (0x04EF, 0x0443, 0x0304),
    (0x04F0, 0x0423, 0x0308),
    (0x04F1, 0x0443, 0x0308),
    (0x04F2, 0x0423, 0x030B),
    (0x04F3, 0x0443, 0x030B),
    (0x04F4, 0x0427, 0x0308),
    (0x04F5, 0x0447, 0x0308),
    (0x04F8, 0x042B, 0x0308),
    (0x04F9, 0x044B, 0x0308),
    (0x1E00, 0x0041, 0x0325),
    (0x1E01, 0x0061, 0x0325),
    (0x1E02, 0x0042, 0x0307),
    (0x1E03, 0x0062, 0x0307),
    (0x1E04, 0x0042, 0x0323),
    (0x1E05, 0x0062, 0x0323),
    (0x1E06, 0x0042, 0x0331),
    (0x1E07, 0x0062, 0x0331),
    (0x1E08, 0x00C7, 0x0301),
    (0x1E09, 0x00E7, 0x0301),
    (0x1E0A, 0x0044, 0x0307),
    (0x1E0B, 0x0064, 0x0307),
    (0x1E0C, 0x0044, 0x0323),
    (0x1E0D, 0x0064, 0x0323),
    (0x1E0E, 0x0044, 0x0331),
    (0x1E0F, 0x0064, 0x0331),
    (0x1E10, 0x0044, 0x0327),
    (0x1E11, 0x0064, 0x0327),
    (0x1E12, 0x0044, 0x032D),
    (0x1E13, 0x0064, 0x032D),
    (0x1E14, 0x0112, 0x0300),
    (0x1E15, 0x0113, 0x0300),
    (0x1E16, 0x0112, 0x0301),
    (0x1E17, 0x0113, 0x0301),
    (0x1E18, 0x0045, 0x032D),
    (0x1E19, 0x0065, 0x032D),
    (0x1E1A, 0x0045, 0x0330),
    (0x1E1B, 0x0065, 0x0330),
    (0x1E1C, 0x0228, 0x0306),
    (0x1E1D, 0x0229, 0x0306),
    (0x1E1E, 0x0046, 0x0307),
    (0x1E1F, 0x0066, 0x0307),
    (0x1E20, 0x0047, 0x0304),
    (0x1E21, 0x0067, 0x0304),
    (0x1E22, 0x0048, 0x0307),
    (0x1E23, 0x0068, 0x0307),
    (0x1E24, 0x0048, 0x0323),
    (0x1E25, 0x0068, 0x0323),
    (0x1E26, 0x0048, 0x0308),
    (0x1E27, 0x0068, 0x0308),
    (0x1E28, 0x0048, 0x0327),
    (0x1E29, 0x0068, 0x0327),
    (0x1E2A, 0x0048, 0x032E),
    (0x1E2B, 0x0068, 0x032E),
    (0x1E2C, 0x0049, 0x0330),
    (0x1E2D, 0x0069, 0x0330),
    (0x1E2E, 0x00CF, 0x0301),
    (0x1E2F, 0x00EF, 0x0301),
    (0x1E30, 0x004B, 0x0301),
    (0x1E31, 0x006B, 0x0301),
    (0x1E32, 0x004B, 0x0323),
    (0x1E33, 0x006B, 0x0323),
    (0x1E34, 0x004B, 0x0331),
    (0x1E35, 0x006B, 0x0331),
    (0x1E36, 0x004C, 0x0323),
    (0x1E37, 0x006C, 0x0323),
    (0x1E38, 0x1E36, 0x0304),
    (0x1E39, 0x1E37, 0x0304),
    (0x1E3A, 0x004C, 0x0331),
    (0x1E3B, 0x006C, 0x0331),
    (0x1E3C, 0x004C, 0x032D),
    (0x1E3D, 0x006C, 0x032D),
    (0x1E3E, 0x004D, 0x0301),
    (0x1E3F, 0x006D, 0x0301),
    (0x1E40, 0x004D, 0x0307),
    (0x1E41, 0x006D, 0x0307),
    (0x1E42, 0x004D, 0x0323),
    (0x1E43, 0x006D, 0x0323),
    (0x1E44, 0x004E, 0x0307),
    (0x1E45, 0x006E, 0x0307),
    (0x1E46, 0x004E, 0x0323),
    (0x1E47, 0x006E, 0x0323),
    (0x1E48, 0x004E, 0x0331),
    (0x1E49, 0x006E, 0x0331),
    (0x1E4A, 0x004E, 0x032D),
    (0x1E4B, 0x006E, 0x032D),
    (0x1E4C, 0x00D5, 0x0301),
    (0x1E4D, 0x00F5, 0x0301),
    (0x1E4E, 0x00D5, 0x0308),
    (0x1E4F, 0x00F5, 0x0308),
    (0x1E50, 0x014C, 0x0300),
    (0x1E51, 0x014D, 0x0300),
    (0x1E52, 0x014C, 0x0301),
    (0x1E53, 0x014D, 0x0301),
    (0x1E54, 0x0050, 0x0301),
    (0x1E55, 0x0070, 0x0301),
    (0x1E56, 0x0050, 0x0307),
    (0x1E57, 0x0070, 0x0307),
    (0x1E58, 0x0052, 0x0307),
    (0x1E59, 0x0072, 0x0307),
    (0x1E5A, 0x0052, 0x0323),
    (0x1E5B, 0x0072, 0x0323),
    (0x1E5C, 0x1E5A, 0x0304),
    (0x1E5D, 0x1E5B, 0x0304),
    (0x1E5E, 0x0052, 0x0331),
    (0x1E5F, 0x0072, 0x0331),
    (0x1E60, 0x0053, 0x0307),
    (0x1E61, 0x0073, 0x0307),
    (0x1E62, 0x0053, 0x0323),
    (0x1E63, 0x0073, 0x0323),
    (0x1E64, 0x015A, 0x0307),
    (0x1E65, 0x015B, 0x0307),
    (0x1E66, 0x0160, 0x0307),
    (0x1E67, 0x0161, 0x0307),
    (0x1E68, 0x1E62, 0x0307),
    (0x1E69, 0x1E63, 0x0307),
    (0x1E6A, 0x0054, 0x0307),
    (0x1E6B, 0x0074, 0x0307),
    (0x1E6C, 0x0054, 0x0323),
    (0x1E6D, 0x0074, 0x0323),
    (0x1E6E, 0x0054, 0x0331),
    (0x1E6F, 0x0074, 0x0331),
    (0x1E70, 0x0054, 0x032D),
    (0x1E71, 0x0074, 0x032D),
    (0x1E72, 0x0055, 0x0324),
    (0x1E73, 0x0075, 0x0324),
    (0x1E74, 0x0055, 0x0330),
    (0x1E75, 0x0075, 0x0330),
    (0x1E76, 0x0055, 0x032D),
    (0x1E77, 0x0075, 0x032D),
    (0x1E78, 0x0168, 0x0301),
    (0x1E79, 0x0169, 0x0301),
    (0x1E7A, 0x016A, 0x0308),
    (0x1E7B, 0x016B, 0x0308),
    (0x1E7C, 0x0056, 0x0303),
    (0x1E7D, 0x0076, 0x0303),
    (0x1E7E, 0x0056, 0x0323),
    (0x1E7F, 0x0076, 0x0323),
    (0x1E80, 0x0057, 0x0300),
    (0x1E81, 0x0077, 0x0300),
    (0x1E82, 0x0057, 0x0301),
    (0x1E83, 0x0077, 0x0301),
    (0x1E84, 0x0057, 0x0308),
    (0x1E85, 0x0077, 0x0308),
    (0x1E86, 0x0057, 0x0307),
    (0x1E87, 0x0077, 0x0307),
    (0x1E88, 0x0057, 0x0323),
    (0x1E89, 0x0077, 0x0323),
    (0x1E8A, 0x0058, 0x0307),
    (0x1E8B, 0x0078, 0x0307),
    (0x1E8C, 0x0058, 0x0308),
    (0x1E8D, 0x0078, 0x0308),
    (0x1E8E, 0x0059, 0x0307),
    (0x1E8F, 0x0079, 0x0307),
    (0x1E90, 0x005A, 0x0302),
    (0x1E91, 0x007A, 0x0302),
    (0x1E92, 0x005A, 0x0323),
    (0x1E93, 0x007A, 0x0323),
    (0x1E94, 0x005A, 0x0331),
    (0x1E95, 0x007A, 0x0331),
    (0x1E96, 0x0068, 0x0331),
    (0x1E97, 0x0074, 0x0308),
    (0x1E98, 0x0077, 0x030A),
    (0x1E99, 0x0079, 0x030A),
    (0x1E9B, 0x017F, 0x0307),
    (0x1EA0, 0x0041, 0x0323),
    (0x1EA1, 0x0061, 0x0323),
    (0x1EA2, 0x0041, 0x0309),
    (0x1EA3, 0x0061, 0x0309),
    (0x1EA4, 0x00C2, 0x0301),
    (0x1EA5, 0x00E2, 0x0301),
    (0x1EA6, 0x00C2, 0x0300),
    (0x1EA7, 0x00E2, 0x0300),
    (0x1EA8, 0x00C2, 0x0309),
    (0x1EA9, 0x00E2, 0x0309),
    (0x1EAA, 0x00C2, 0x0303),
    (0x1EAB, 0x00E2, 0x0303),
    (0x1EAC, 0x1EA0, 0x0302),
    (0x1EAD, 0x1EA1, 0x0302),
    (0x1EAE, 0x0102, 0x0301),
    (0x1EAF, 0x0103, 0x0301),
    (0x1EB0, 0x0102, 0x0300),
    (0x1EB1, 0x0103, 0x0300),
    (0x1EB2, 0x0102, 0x0309),
    (0x1EB3, 0x0103, 0x0309),
    (0x1EB4, 0x0102, 0x0303),
    (0x1EB5, 0x0103, 0x0303),
    (0x1EB6, 0x1EA0, 0x0306),
    (0x1EB7, 0x1EA1, 0x0306),
    (0x1EB8, 0x0045, 0x0323),
    (0x1EB9, 0x0065, 0x0323),
    (0x1EBA, 0x0045, 0x0309),
    (0x1EBB, 0x0065, 0x0309),
    (0x1EBC, 0x0045, 0x0303),
    (0x1EBD, 0x0065, 0x0303),
    (0x1EBE, 0x00CA, 0x0301),
    (0x1EBF, 0x00EA, 0x0301),
    (0x1EC0, 0x00CA, 0x0300),
    (0x1EC1, 0x00EA, 0x0300),
    (0x1EC2, 0x00CA, 0x0309),
    (0x1EC3, 0x00EA, 0x0309),
    (0x1EC4, 0x00CA, 0x0303),
    (0x1EC5, 0x00EA, 0x0303),
    (0x1EC6, 0x1EB8, 0x0302),
    (0x1EC7, 0x1EB9, 0x0302),
    (0x1EC8, 0x0049, 0x0309),
    (0x1EC9, 0x0069, 0x0309),
    (0x1ECA, 0x0049, 0x0323),
    (0x1ECB, 0x0069, 0x0323),
    (0x1ECC, 0x004F, 0x0323),
    (0x1ECD, 0x006F, 0x0323),
    (0x1ECE, 0x004F, 0x0309),
    (0x1ECF, 0x006F, 0x0309),
    (0x1ED0, 0x00D4, 0x0301),
    (0x1ED1, 0x00F4, 0x0301),
    (0x1ED2, 0x00D4, 0x0300),
    (0x1ED3, 0x00F4, 0x0300),
    (0x1ED4, 0x00D4, 0x0309),
    (0x1ED5, 0x00F4, 0x0309),
    (0x1ED6, 0x00D4, 0x0303),
    (0x1ED7, 0x00F4, 0x0303),
    (0x1ED8, 0x1ECC, 0x0302),
    (0x1ED9, 0x1ECD, 0x0302),
    (0x1EDA, 0x01A0, 0x0301),
    (0x1EDB, 0x01A1, 0x0301),
    (0x1EDC, 0x01A0, 0x0300),
    (0x1EDD, 0x01A1, 0x0300),
    (0x1EDE, 0x01A0, 0x0309),
    (0x1EDF, 0x01A1, 0x0309),
    (0x1EE0, 0x01A0, 0x0303),
    (0x1EE1, 0x01A1, 0x0303),
    (0x1EE2, 0x01A0, 0x0323),
    (0x1EE3, 0x01A1, 0x0323),
    (0x1EE4, 0x0055, 0x0323),
    (0x1EE5, 0x0075, 0x0323),
    (0x1EE6, 0x0055, 0x0309),
    (0x1EE7, 0x0075, 0x0309),
    (0x1EE8, 0x01AF, 0x0301),
    (0x1EE9, 0x01B0, 0x0301),
    (0x1EEA, 0x01AF, 0x0300),
    (0x1EEB, 0x01B0, 0x0300),
    (0x1EEC, 0x01AF, 0x0309),
    (0x1EED, 0x01B0, 0x0309),
    (0x1EEE, 0x01AF, 0x0303),
    (0x1EEF, 0x01B0, 0x0303),
    (0x1EF0, 0x01AF, 0x0323),
    (0x1EF1, 0x01B0, 0x0323),
    (0x1EF2, 0x0059, 0x0300),
    (0x1EF3, 0x0079, 0x0300),
    (0x1EF4, 0x0059, 0x0323),
    (0x1EF5, 0x0079, 0x0323),
    (0x1EF6, 0x0059, 0x0309),
    (0x1EF7, 0x0079, 0x0309),
    (0x1EF8, 0x0059, 0x0303),
    (0x1EF9, 0x0079, 0x0303),
];

// ---------------------------------------------------------------------------
// The reader callers use
// ---------------------------------------------------------------------------

/// A repository opened for reading, with the index loaded once so a scan
/// of N files costs one index parse rather than N process spawns.
#[derive(Debug, Clone)]
pub struct RepoView {
    pub layout: RepoLayout,
    tracked: BTreeSet<String>,
    /// The canonical decomposition of every tracked path that carries
    /// non-ASCII text, so an NFD name from `readdir` still finds the NFC
    /// path Git recorded (RA-018). Empty for the overwhelming majority of
    /// repositories, whose paths are pure ASCII.
    tracked_decomposed: BTreeSet<String>,
    index_readable: bool,
    limits: Vec<ViewLimit>,
}

impl RepoView {
    /// Open the repository containing `root`, or `None` when `root` is not
    /// inside a work tree. Never spawns a process.
    pub fn open(root: &Path) -> Option<RepoView> {
        let layout = discover(root)?;
        let (tracked, index_readable, mut limits) = match read_index(&layout.git_dir) {
            Ok(paths) => (paths, true, Vec::new()),
            Err(limit) => (BTreeSet::new(), false, vec![limit]),
        };
        let tracked_decomposed: BTreeSet<String> = tracked
            .iter()
            .filter(|p| !p.is_ascii())
            .map(|p| canonical_decomposition(p))
            .collect();
        limits.shrink_to_fit();
        Some(RepoView {
            layout,
            tracked,
            tracked_decomposed,
            index_readable,
            limits,
        })
    }

    /// Whether `rel` names a path in the index.
    ///
    /// Exact bytes first, then canonical equivalence — the second lookup is
    /// what stops a committed `.env` under an accented directory name from
    /// reading `Untracked` on macOS (RA-018). Pure-ASCII paths, which is
    /// nearly all of them, never reach the fold.
    fn is_tracked(&self, rel: &str) -> bool {
        if self.tracked.contains(rel) {
            return true;
        }
        !rel.is_ascii()
            && self
                .tracked_decomposed
                .contains(&canonical_decomposition(rel))
    }

    /// `path`'s status. `path` must be inside the work tree; anything else
    /// answers [`PathStatus::Untracked`] rather than guessing.
    pub fn status_of(&self, path: &Path) -> PathStatus {
        let Some(rel) = self.repo_relative(path) else {
            return PathStatus::Untracked;
        };
        if !self.index_readable {
            return PathStatus::Unknown;
        }
        if self.is_tracked(&rel) {
            return PathStatus::Tracked;
        }
        let dir_rel = match rel.rfind('/') {
            Some(i) => rel[..i].to_string(),
            None => String::new(),
        };
        let rules = load_ignore_rules(&self.layout, &dir_rel);
        if rules.is_ignored(&rel, path.is_dir()) {
            PathStatus::Ignored
        } else {
            PathStatus::Untracked
        }
    }

    /// The work-tree-relative, forward-slash form of `path`.
    pub fn repo_relative(&self, path: &Path) -> Option<String> {
        let rel = path.strip_prefix(&self.layout.work_tree).ok()?;
        Some(rel.to_string_lossy().replace('\\', "/"))
    }

    /// Bounds hit while opening, for honest scan warnings.
    pub fn limits(&self) -> &[ViewLimit] {
        &self.limits
    }
}

/// A [`RepoView`] with the ignore rules for one directory loaded once, so
/// a directory holding many `.env*` files pays for its rules a single time.
pub struct DirView<'a> {
    view: &'a RepoView,
    rules: IgnoreRules,
    dir_rel: String,
}

impl RepoView {
    /// Open a per-directory view. `dir_rel` is work-tree-relative with
    /// forward slashes (empty for the root).
    pub fn dir_view(&self, dir_rel: &str) -> DirView<'_> {
        DirView {
            view: self,
            rules: load_ignore_rules(&self.layout, dir_rel),
            dir_rel: dir_rel.to_string(),
        }
    }
}

impl DirView<'_> {
    /// Status of `name` inside this directory.
    pub fn status_of_name(&self, name: &str, is_dir: bool) -> PathStatus {
        let rel = if self.dir_rel.is_empty() {
            name.to_string()
        } else {
            format!("{}/{name}", self.dir_rel)
        };
        if !self.view.index_readable {
            return PathStatus::Unknown;
        }
        if self.view.is_tracked(&rel) {
            return PathStatus::Tracked;
        }
        if self.rules.is_ignored(&rel, is_dir) {
            PathStatus::Ignored
        } else {
            PathStatus::Untracked
        }
    }

    pub fn limits(&self) -> &[ViewLimit] {
        self.rules.limits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_star_does_not_cross_a_slash() {
        assert!(glob_match_path(&["*.env"], &["a.env"]));
        assert!(!glob_match_path(&["*.env"], &["sub", "a.env"]));
        assert!(glob_match_path(&["**", "*.env"], &["sub", "a.env"]));
    }

    #[test]
    fn character_classes_and_ranges() {
        assert!(glob_match_path(&["[abc].env"], &["b.env"]));
        assert!(!glob_match_path(&["[abc].env"], &["d.env"]));
        assert!(glob_match_path(&["[a-c].env"], &["c.env"]));
        assert!(glob_match_path(&["[!a-c].env"], &["d.env"]));
        assert!(!glob_match_path(&["[!a-c].env"], &["a.env"]));
    }

    #[test]
    fn trailing_spaces_are_trimmed_unless_escaped() {
        assert_eq!(trim_trailing_unescaped_spaces("a.env   "), "a.env");
        assert_eq!(trim_trailing_unescaped_spaces("a.env\\ "), "a.env\\ ");
    }

    #[test]
    fn varint_matches_gits_encoding() {
        // encode_varint(0) == [0x00]; encode_varint(127) == [0x7f];
        // encode_varint(128) == [0x80, 0x00]; encode_varint(255) == [0x80, 0x7f]
        let mut p = 0;
        assert_eq!(decode_varint(&[0x00], &mut p), Some(0));
        p = 0;
        assert_eq!(decode_varint(&[0x7f], &mut p), Some(127));
        p = 0;
        assert_eq!(decode_varint(&[0x80, 0x00], &mut p), Some(128));
        p = 0;
        assert_eq!(decode_varint(&[0x80, 0x7f], &mut p), Some(255));
    }

    #[test]
    fn negation_reincludes_within_the_same_file() {
        let mut patterns = Vec::new();
        parse_ignore_file("", "*.env\n!keep.env\n", &mut patterns);
        let rules = IgnoreRules {
            patterns,
            limits: Vec::new(),
        };
        assert!(rules.is_ignored("a.env", false));
        assert!(!rules.is_ignored("keep.env", false));
    }

    #[test]
    fn an_excluded_directory_keeps_its_children_excluded() {
        let mut patterns = Vec::new();
        parse_ignore_file("", "build/\n!build/a.env\n", &mut patterns);
        let rules = IgnoreRules {
            patterns,
            limits: Vec::new(),
        };
        // Git cannot re-include a file whose parent directory is excluded.
        assert!(rules.is_ignored("build/a.env", false));
    }

    #[test]
    fn anchored_patterns_only_match_at_their_base() {
        let mut patterns = Vec::new();
        parse_ignore_file("", "/a.env\n", &mut patterns);
        let rules = IgnoreRules {
            patterns,
            limits: Vec::new(),
        };
        assert!(rules.is_ignored("a.env", false));
        assert!(!rules.is_ignored("sub/a.env", false));
    }

    /// The decomposition table is generated, so what has to be pinned is
    /// that it stayed generated: sorted, unique, in range, and still saying
    /// what Unicode says. A hand edit that broke the ordering would make
    /// `binary_search_by_key` miss silently, and a missed lookup reads as
    /// `Untracked` — the exact failure RA-018 describes.
    #[test]
    fn decomposition_table_is_well_formed() {
        assert_eq!(
            CANONICAL_DECOMPOSITION.len(),
            579,
            "the generator command in the table's documentation emits 579 entries"
        );
        for pair in CANONICAL_DECOMPOSITION.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "the table must be sorted and free of duplicates: {:#06X} then {:#06X}",
                pair[0].0,
                pair[1].0
            );
        }
        for (composed, base, _) in CANONICAL_DECOMPOSITION {
            let in_range =
                (0x00C0..=0x04FF).contains(composed) || (0x1E00..=0x1EFF).contains(composed);
            assert!(in_range, "{composed:#06X} is outside the declared ranges");
            assert_ne!(composed, base, "{composed:#06X} decomposes to itself");
        }
        // Hand-verified against the Unicode character database.
        for (composed, base, mark) in [
            (0x00E9u16, 0x0065u16, 0x0301u16), // é  LATIN SMALL LETTER E WITH ACUTE
            (0x00F1, 0x006E, 0x0303),          // ñ  ... N WITH TILDE
            (0x00C5, 0x0041, 0x030A),          // Å  ... A WITH RING ABOVE
            (0x0151, 0x006F, 0x030B),          // ő  ... O WITH DOUBLE ACUTE
            (0x01D4, 0x0075, 0x030C),          // ǔ  ... U WITH CARON
            (0x01D5, 0x00DC, 0x0304),          // Ǖ  ... U WITH DIAERESIS AND MACRON
            (0x0439, 0x0438, 0x0306),          // й  CYRILLIC SMALL LETTER SHORT I
            (0x03AC, 0x03B1, 0x0301),          // ά  GREEK SMALL LETTER ALPHA WITH TONOS
            (0x1EC7, 0x1EB9, 0x0302),          // ệ  ... E WITH CIRCUMFLEX AND DOT BELOW
            (0x0340, 0x0300, 0x0000),          //    a singleton decomposition
        ] {
            let at = CANONICAL_DECOMPOSITION
                .binary_search_by_key(&composed, |(c, _, _)| *c)
                .unwrap_or_else(|_| panic!("{composed:#06X} is missing from the table"));
            assert_eq!(CANONICAL_DECOMPOSITION[at], (composed, base, mark));
        }
    }

    #[test]
    fn canonical_decomposition_folds_nfc_onto_nfd() {
        // The pair that matters: Git's index holds the left form, macOS
        // `readdir` hands back the right one (RA-018).
        assert_eq!(canonical_decomposition("caf\u{e9}"), "caf\u{65}\u{301}");
        assert_eq!(
            canonical_decomposition("caf\u{65}\u{301}"),
            "caf\u{65}\u{301}",
            "an already decomposed name must be a fixed point"
        );
        // Two levels: U+1EC7 -> U+1EB9 + U+0302 -> U+0065 + U+0323 + U+0302.
        assert_eq!(canonical_decomposition("\u{1ec7}"), "\u{65}\u{323}\u{302}");
        // Hangul needs no table: U+D55C -> U+1112 U+1161 U+11AB.
        assert_eq!(
            canonical_decomposition("\u{d55c}"),
            "\u{1112}\u{1161}\u{11ab}"
        );
        // U+AC00 has no trailing consonant, so only two jamo come out.
        assert_eq!(canonical_decomposition("\u{ac00}"), "\u{1100}\u{1161}");
        // ASCII is untouched, and distinct names stay distinct: folding
        // must not become accent-insensitive matching.
        assert_eq!(canonical_decomposition("a/b/.env"), "a/b/.env");
        assert_ne!(
            canonical_decomposition("r\u{e9}sum\u{e9}"),
            canonical_decomposition("resume")
        );
        // Out-of-range scripts are passed through unchanged rather than
        // half-folded; CJK has no canonical decomposition at all.
        assert_eq!(
            canonical_decomposition("\u{65e5}\u{672c}"),
            "\u{65e5}\u{672c}"
        );
    }

    /// EWAH is the only container format this module decodes beyond `DIRC`
    /// itself, and it is the one that decides whether a split index's
    /// deleted entries are still reported as tracked (RA-007).
    #[test]
    fn ewah_decodes_a_git_produced_bitmap() {
        // Captured from `git update-index --split-index` on a three-entry
        // repository: bit_size 3, two words — a run-length word declaring
        // one literal, then the literal 0b111.
        let bytes = [
            0x00, 0x00, 0x00, 0x03, // bit_size
            0x00, 0x00, 0x00, 0x02, // word_count
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // rlw: 1 literal word
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // literal: bits 0,1,2
            0x00, 0x00, 0x00, 0x00, // rlw offset
        ];
        let (set, len) = decode_ewah(&bytes, 3).unwrap();
        assert_eq!(len, bytes.len());
        assert_eq!(set, BTreeSet::from([0, 1, 2]));

        // An empty bitmap, as written for "nothing was deleted".
        let empty = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let (set, len) = decode_ewah(&empty, 100).unwrap();
        assert_eq!(len, empty.len());
        assert!(set.is_empty());

        // A run of set words is what a hostile bitmap would use to demand
        // 2^38 positions out of twenty bytes; `max_bit` refuses it instead.
        let huge = [
            0xFF, 0xFF, 0xFF, 0xFF, // bit_size: 4 294 967 295
            0x00, 0x00, 0x00, 0x01, // one word
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // rlw: 2^31-ish clean ones
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(decode_ewah(&huge, 100).is_err());
    }

    #[test]
    fn unanchored_patterns_match_at_any_depth() {
        let mut patterns = Vec::new();
        parse_ignore_file("", "a.env\n", &mut patterns);
        let rules = IgnoreRules {
            patterns,
            limits: Vec::new(),
        };
        assert!(rules.is_ignored("a.env", false));
        assert!(rules.is_ignored("sub/deep/a.env", false));
    }
}
