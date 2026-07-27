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
//! Every read is capped ([`MAX_INDEX_BYTES`], [`MAX_IGNORE_BYTES`],
//! [`MAX_IGNORE_PATTERNS`], [`MAX_GITDIR_HOPS`]). Exceeding a bound
//! degrades the answer to "unknown" and is reported to the caller — it
//! never panics, never allocates without limit, and never silently claims
//! a clean result.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Largest `.git/index` this module will read (64 MiB). Beyond it the
/// tracked-file answer degrades to `Unknown`.
pub const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

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
    /// `.git/index` exists but is not a format this reader understands.
    IndexUnreadable { why: String },
    /// At least one ignore file exceeded [`MAX_IGNORE_BYTES`] and was skipped.
    IgnoreFileTooLarge { path: String },
    /// The pattern budget was exhausted; later rules were not loaded.
    IgnorePatternBudget,
}

impl ViewLimit {
    pub fn describe(&self) -> String {
        match self {
            ViewLimit::IndexTooLarge { bytes } => format!(
                "this repository's Git index is {bytes} bytes, over Tethra's {MAX_INDEX_BYTES}-byte \
                 read limit — files are reported as untracked rather than guessed"
            ),
            ViewLimit::IndexUnreadable { why } => {
                format!("this repository's Git index could not be parsed ({why}) — files are \
                         reported as untracked rather than guessed")
            }
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

/// Attempt a full index parse with a given object-id length.
///
/// Returns the set of tracked paths (forward-slash, relative to the work
/// tree) on success. `Err` carries a short reason for the caller's warning.
fn parse_index_with_oid_len(buf: &[u8], oid_len: usize) -> Result<BTreeSet<String>, String> {
    if buf.len() < 12 {
        return Err("shorter than a DIRC header".into());
    }
    if &buf[0..4] != b"DIRC" {
        return Err("missing the DIRC signature".into());
    }
    let version = be_u32(buf, 4).ok_or("truncated version")?;
    if !matches!(version, 2 | 3 | 4) {
        return Err(format!("unsupported index version {version}"));
    }
    let count = be_u32(buf, 8).ok_or("truncated entry count")? as usize;
    // A hostile or corrupt header must not make us allocate: every entry
    // needs at least the fixed part, so the count is bounded by the file.
    let min_entry = 40 + oid_len + 2 + 1;
    if count.saturating_mul(min_entry) > buf.len() {
        return Err("entry count exceeds the file size".into());
    }

    let mut out = BTreeSet::new();
    let mut pos = 12usize;
    let mut previous: Vec<u8> = Vec::new();

    for _ in 0..count {
        let entry_start = pos;
        // stat data (40) + object id + flags (2)
        let flags_at = pos
            .checked_add(40)
            .and_then(|p| p.checked_add(oid_len))
            .ok_or("entry offset overflow")?;
        let flags = be_u16(buf, flags_at).ok_or("truncated entry flags")?;
        pos = flags_at + 2;
        let extended = flags & 0x4000 != 0;
        if extended {
            if version < 3 {
                return Err("extended flag set in a version-2 index".into());
            }
            // Skip the extra 16-bit flags word.
            if buf.len() < pos + 2 {
                return Err("truncated extended flags".into());
            }
            pos += 2;
        }

        let path: Vec<u8> = if version == 4 {
            let strip = decode_varint(buf, &mut pos).ok_or("truncated path varint")? as usize;
            if strip > previous.len() {
                return Err("prefix strip longer than the previous path".into());
            }
            let nul = buf[pos..]
                .iter()
                .position(|b| *b == 0)
                .ok_or("unterminated path")?;
            let suffix = &buf[pos..pos + nul];
            pos += nul + 1;
            let mut p = previous[..previous.len() - strip].to_vec();
            p.extend_from_slice(suffix);
            p
        } else {
            let nul = buf[pos..]
                .iter()
                .position(|b| *b == 0)
                .ok_or("unterminated path")?;
            let p = buf[pos..pos + nul].to_vec();
            pos += nul + 1;
            // Versions 2 and 3 pad each entry with NULs to a multiple of
            // eight bytes, measured from the start of the entry.
            let unpadded = pos - entry_start;
            let padded = unpadded.div_ceil(8) * 8;
            pos = entry_start + padded;
            if pos > buf.len() {
                return Err("padding runs past the end of the index".into());
            }
            p
        };

        previous = path.clone();
        // Index paths are always forward-slash and relative to the work
        // tree. Non-UTF-8 paths cannot name a `.env*` file we care about,
        // so they are recorded lossily rather than aborting the parse.
        out.insert(String::from_utf8_lossy(&path).into_owned());
    }

    // Validate the tail: what follows the entries must be the trailing
    // checksum on its own, or one or more extensions. This is what makes
    // the object-id-length probe below self-checking instead of a guess.
    let remaining = buf.len().saturating_sub(pos);
    if remaining < oid_len {
        return Err("no room for the index trailer".into());
    }
    if remaining > oid_len {
        let sig = buf.get(pos..pos + 4).ok_or("truncated extension header")?;
        let plausible = sig.iter().all(|b| b.is_ascii_alphabetic());
        if !plausible {
            return Err("unrecognised bytes where an extension header was expected".into());
        }
    }
    Ok(out)
}

/// Every path in `.git/index`, or a reason it could not be read.
///
/// The object-id length (20 for SHA-1, 32 for SHA-256) is not recorded in
/// the index header, so both are attempted; the tail validation inside
/// [`parse_index_with_oid_len`] rejects the wrong one.
pub fn read_index(git_dir: &Path) -> Result<BTreeSet<String>, ViewLimit> {
    let path = git_dir.join("index");
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        // No index at all (a freshly `git init`ed repository): nothing is
        // tracked, which is a complete and correct answer.
        Err(_) => return Ok(BTreeSet::new()),
    };
    if !meta.is_file() {
        return Ok(BTreeSet::new());
    }
    if meta.len() > MAX_INDEX_BYTES {
        return Err(ViewLimit::IndexTooLarge { bytes: meta.len() });
    }
    let buf =
        std::fs::read(&path).map_err(|e| ViewLimit::IndexUnreadable { why: e.to_string() })?;
    let sha1 = parse_index_with_oid_len(&buf, 20);
    if let Ok(paths) = sha1 {
        return Ok(paths);
    }
    match parse_index_with_oid_len(&buf, 32) {
        Ok(paths) => Ok(paths),
        Err(why) => Err(ViewLimit::IndexUnreadable {
            why: sha1.err().unwrap_or(why),
        }),
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
    fn go(pattern: &[&str], text: &[&str]) -> bool {
        match pattern.first() {
            None => text.is_empty(),
            Some(&"**") => {
                for skip in 0..=text.len() {
                    if go(&pattern[1..], &text[skip..]) {
                        return true;
                    }
                }
                false
            }
            Some(seg) => {
                let Some(head) = text.first() else {
                    return false;
                };
                let p: Vec<char> = seg.chars().collect();
                let t: Vec<char> = head.chars().collect();
                glob_match_segment(&p, &t) && go(&pattern[1..], &text[1..])
            }
        }
    }
    go(pattern, text)
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
// The reader callers use
// ---------------------------------------------------------------------------

/// A repository opened for reading, with the index loaded once so a scan
/// of N files costs one index parse rather than N process spawns.
#[derive(Debug, Clone)]
pub struct RepoView {
    pub layout: RepoLayout,
    tracked: BTreeSet<String>,
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
        limits.shrink_to_fit();
        Some(RepoView {
            layout,
            tracked,
            index_readable,
            limits,
        })
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
        if self.tracked.contains(&rel) {
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
        if self.view.tracked.contains(&rel) {
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
