//! Local Git integration for the scanner.
//!
//! All operations shell out to the user's `git` binary and run entirely
//! locally — no source code, diffs, or findings ever leave the machine. We
//! avoid a heavy libgit2 dependency; the trade-off is that `git` must be on
//! PATH (checked via [`git_available`]).
//!
//! For staged and historical content we read blobs/diffs through git so the
//! scanner sees exactly what is committed, not just the working tree.

use crate::error::{CoreError, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A unit of text to scan, with a label for findings.
pub struct ScanUnit {
    pub label: String,
    pub content: String,
}

// ---------------------------------------------------------------------------
// Bounded git execution (CONC-06 / GScan-03)
//
// Every git subprocess runs under an explicit wall-clock timeout and output
// byte cap; on violation the child is killed and reaped, never orphaned.
// History scanning streams `git log -p` line-by-line instead of buffering
// the whole patch stream, with per-line, per-unit, total-retained, and
// duration limits. Hitting any limit is reported as INCOMPLETE COVERAGE —
// never as a clean scan.
// ---------------------------------------------------------------------------

/// Limits applied to one git subprocess.
#[derive(Debug, Clone)]
pub struct GitLimits {
    /// Wall-clock limit for the whole subprocess.
    pub timeout: Duration,
    /// Maximum stdout bytes read (streamed or captured).
    pub max_output_bytes: u64,
    /// Maximum bytes retained per line when streaming (longer lines are
    /// truncated; the scanner skips over-long lines anyway).
    pub max_line_bytes: usize,
    /// Maximum bytes retained per scan unit (one commit:file); beyond this
    /// the unit is truncated and reported as a coverage warning.
    pub max_unit_bytes: usize,
    /// Maximum bytes retained across ALL units of one scan; beyond this the
    /// scan stops early and is reported incomplete.
    pub max_retained_bytes: u64,
}

/// Debug-build-only numeric override so deterministic tests can drive the
/// limits down without waiting minutes; ignored by release builds. `suffix`
/// resolves through the `TETHRA_*`/`API_TRACKER_*` pair.
fn env_limit(suffix: &str, default: u64) -> u64 {
    if cfg!(debug_assertions) {
        if let Some(Ok(v)) = crate::envcompat::var(suffix) {
            if let Ok(n) = v.parse() {
                return n;
            }
        }
    }
    default
}

impl GitLimits {
    /// Limits for ordinary short git commands (rev-parse, diff --name-only,
    /// cat-file, show, config). Generous but finite: a hung git (dead
    /// network mount, wedged lock) must not hang API Tracker forever.
    pub fn command() -> Self {
        GitLimits {
            timeout: Duration::from_millis(env_limit("GIT_TIMEOUT_MS", 30_000)),
            max_output_bytes: env_limit("GIT_MAX_OUTPUT_BYTES", 32 * 1024 * 1024),
            max_line_bytes: 1024 * 1024,
            max_unit_bytes: MAX_FILE_BYTES as usize,
            max_retained_bytes: 64 * 1024 * 1024,
        }
    }

    /// Limits for history scanning (`git log -p`), which can stream far
    /// more data than it retains. The duration bound is larger because a
    /// full-history scan of a big repository is legitimately slow.
    pub fn history() -> Self {
        GitLimits {
            timeout: Duration::from_millis(env_limit("GIT_HISTORY_TIMEOUT_MS", 180_000)),
            max_output_bytes: env_limit("GIT_HISTORY_MAX_STREAM_BYTES", 1024 * 1024 * 1024),
            max_line_bytes: 64 * 1024,
            max_unit_bytes: MAX_FILE_BYTES as usize,
            max_retained_bytes: env_limit("GIT_HISTORY_MAX_RETAINED_BYTES", 64 * 1024 * 1024),
        }
    }
}

/// Reaps the child on every exit path (including panics): kill is a no-op
/// for an already-exited child, and `wait` collects the zombie so no git
/// process is ever orphaned by a timeout, cap, error, or cancellation.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The git binary to spawn. Debug builds honour `TETHRA_GIT_BINARY` (or
/// the legacy `API_TRACKER_GIT_BINARY`) so tests can substitute a
/// deterministic fake (hung/slow/flooding git); release builds always use
/// `git` from PATH.
fn git_program() -> String {
    if cfg!(debug_assertions) {
        if let Some(Ok(p)) = crate::envcompat::var("GIT_BINARY") {
            if !p.is_empty() {
                return p;
            }
        }
    }
    "git".to_string()
}

fn spawn_git(repo: &Path, args: &[&str]) -> Result<Child> {
    Command::new(git_program())
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CoreError::InvalidInput(
                    "git is not installed or not on PATH; repository scanning needs it".into(),
                )
            } else {
                CoreError::Io(e)
            }
        })
}

/// Captured output of a bounded git run that finished within its limits.
pub struct GitCapture {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub success: bool,
    pub status_code: Option<i32>,
}

const READ_CHUNK: usize = 64 * 1024;
const STDERR_CAP: usize = 64 * 1024;

/// Spawn a reader thread pumping stdout chunks over a bounded channel (the
/// bound provides backpressure, so a flooding child cannot outrun the
/// consumer's caps in memory).
fn pump_stdout(
    stdout: std::process::ChildStdout,
) -> (
    mpsc::Receiver<std::io::Result<Vec<u8>>>,
    std::thread::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::sync_channel::<std::io::Result<Vec<u8>>>(16);
    let handle = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(Ok(buf[..n].to_vec())).is_err() {
                        break; // consumer stopped; child is being killed
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e));
                    break;
                }
            }
        }
    });
    (rx, handle)
}

/// Collect stderr on a thread, capped (diagnostics only; never secret).
fn pump_stderr(stderr: std::process::ChildStderr) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut stderr = stderr;
        let mut out = Vec::new();
        let mut buf = vec![0u8; READ_CHUNK];
        while let Ok(n) = stderr.read(&mut buf) {
            if n == 0 {
                break;
            }
            if out.len() < STDERR_CAP {
                let take = (STDERR_CAP - out.len()).min(n);
                out.extend_from_slice(&buf[..take]);
            }
            // Keep draining past the cap so the child never blocks on a
            // full stderr pipe.
        }
        out
    })
}

fn timeout_error(args: &[&str], limits: &GitLimits) -> CoreError {
    CoreError::InvalidInput(format!(
        "git {} did not finish within {:?}; the repository may be on a hung \
         mount or wedged — the git process was terminated",
        args.first().unwrap_or(&""),
        limits.timeout
    ))
}

/// Run a short git command to completion under limits. Timeout or output
/// overflow kills and reaps the child and returns a loud error — a bounded
/// failure, never a hang and never silently-partial output.
fn run_git_bounded(repo: &Path, args: &[&str], limits: &GitLimits) -> Result<GitCapture> {
    let mut child = spawn_git(repo, args)?;
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut guard = ChildGuard(child);
    let (rx, _reader) = pump_stdout(stdout);
    let stderr_handle = pump_stderr(stderr);

    let deadline = Instant::now() + limits.timeout;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timeout_error(args, limits));
        }
        match rx.recv_timeout(remaining) {
            Ok(Ok(chunk)) => {
                if (out.len() + chunk.len()) as u64 > limits.max_output_bytes {
                    return Err(CoreError::InvalidInput(format!(
                        "git {} produced more than {} bytes of output; refusing to buffer it",
                        args.first().unwrap_or(&""),
                        limits.max_output_bytes
                    )));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(Err(e)) => return Err(CoreError::Io(e)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(timeout_error(args, limits));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break, // EOF
        }
    }
    // Output complete; wait for exit within the same deadline.
    let status = loop {
        match guard.0.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err(timeout_error(args, limits));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(CoreError::Io(e)),
        }
    };
    let stderr = stderr_handle.join().unwrap_or_default();
    Ok(GitCapture {
        stdout: out,
        stderr,
        success: status.success(),
        status_code: status.code(),
    })
}

/// Back-compat shim used by the short-command helpers below.
fn run_git(repo: &Path, args: &[&str]) -> Result<GitCapture> {
    run_git_bounded(repo, args, &GitLimits::command())
}

/// Bounded git probe for sibling modules (env governance): same limits as
/// every other short git command, so no caller in the crate can spawn an
/// unbounded git subprocess.
pub(crate) fn run_git_probe(repo: &Path, args: &[&str]) -> Result<GitCapture> {
    run_git_bounded(repo, args, &GitLimits::command())
}

/// Whether `git` is usable.
pub fn git_available() -> bool {
    Command::new(git_program())
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The effective value of a git config key for `repo` (merged across
/// local/global/system scopes, exactly the value git itself would use), or
/// `None` when the key is unset. Errors only when git cannot run.
pub fn config_get(repo: &Path, key: &str) -> Result<Option<String>> {
    let out = run_git(repo, &["config", "--get", key])?;
    if out.success {
        return Ok(Some(
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        ));
    }
    // `git config --get` exits 1 for an unset key. Anything else (malformed
    // config, unusable repo) is a real failure: callers must not assume the
    // default and over-claim what git will do.
    if out.status_code == Some(1) {
        Ok(None)
    } else {
        Err(CoreError::InvalidInput(format!(
            "could not read git config '{key}': {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// The repository root containing `path`, or an error if it is not a repo.
pub fn repo_root(path: &Path) -> Result<PathBuf> {
    let out = run_git(path, &["rev-parse", "--show-toplevel"])?;
    if !out.success {
        return Err(CoreError::InvalidInput(format!(
            "{} is not inside a Git repository",
            path.display()
        )));
    }
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(PathBuf::from(root))
}

/// Names of files staged for commit (added/copied/modified).
pub fn staged_files(repo: &Path) -> Result<Vec<String>> {
    let out = run_git(
        repo,
        &["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
    )?;
    if !out.success {
        return Err(CoreError::InvalidInput(
            "could not list staged files (is this a Git repository?)".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect())
}

/// The staged content of a file (the version that would be committed).
/// Blobs above the scanner's working-tree size cap are skipped (returning
/// `None`) instead of being buffered whole — the same bound the
/// working-tree scan applies, so a multi-GB staged file cannot OOM the
/// pre-commit hook.
pub fn staged_blob(repo: &Path, path: &str) -> Result<Option<Vec<u8>>> {
    let size = run_git(repo, &["cat-file", "-s", &format!(":{path}")])?;
    if size.success {
        if let Ok(bytes) = String::from_utf8_lossy(&size.stdout).trim().parse::<u64>() {
            if bytes > MAX_FILE_BYTES {
                return Ok(None);
            }
        }
    }
    let out = run_git(repo, &["show", &format!(":{path}")])?;
    if !out.success {
        return Ok(None);
    }
    Ok(Some(out.stdout))
}

/// Scan units for everything currently staged.
pub fn staged_units(repo: &Path) -> Result<Vec<ScanUnit>> {
    let mut units = Vec::new();
    for path in staged_files(repo)? {
        if let Some(bytes) = staged_blob(repo, &path)? {
            if crate::scanner::looks_binary(&bytes) {
                continue;
            }
            units.push(ScanUnit {
                label: path.clone(),
                content: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
    }
    Ok(units)
}

/// Added lines across the last `n` commits (or all history when `n` is None),
/// as scan units labelled `commit <short>:<file>`.
/// The current HEAD commit hash of a repository.
pub fn head_commit(repo: &Path) -> Result<String> {
    let out = run_git(repo, &["rev-parse", "HEAD"])?;
    if !out.success {
        return Err(CoreError::InvalidInput(
            "could not read the repository HEAD (no commits yet?)".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Result of a (possibly bounded) history scan: the units collected plus an
/// honest coverage statement. `complete == false` means some history was
/// NOT examined — callers must surface the warnings and must never treat
/// the scan as a verified-clean full scan.
pub struct HistoryScan {
    pub units: Vec<ScanUnit>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

/// Added lines from the commits in `old..new` only (incremental scanning).
pub fn range_added_units(repo: &Path, old: &str, new: &str) -> Result<HistoryScan> {
    range_added_units_with_limits(repo, old, new, &GitLimits::history())
}

pub fn range_added_units_with_limits(
    repo: &Path,
    old: &str,
    new: &str,
    limits: &GitLimits,
) -> Result<HistoryScan> {
    // Both endpoints are commit hashes we recorded/resolved ourselves, but
    // require them to be plain hex so a tampered stored value (e.g.
    // `--output=…`) can never be parsed by git as an option, and pass
    // `--end-of-options` before the range for defense in depth.
    for endpoint in [old, new] {
        if endpoint.is_empty() || !endpoint.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CoreError::InvalidInput(
                "commit range endpoints must be hex commit ids".into(),
            ));
        }
    }
    let range = format!("{old}..{new}");
    let args = [
        "log",
        "-p",
        "--no-color",
        "-U0",
        "--no-merges",
        "--end-of-options",
        range.as_str(),
    ];
    stream_log_units(repo, &args, limits, "commit range")
}

pub fn history_added_units(repo: &Path, n: Option<usize>) -> Result<HistoryScan> {
    history_added_units_with_limits(repo, n, &GitLimits::history())
}

pub fn history_added_units_with_limits(
    repo: &Path,
    n: Option<usize>,
    limits: &GitLimits,
) -> Result<HistoryScan> {
    let count = n.map(|c| format!("-n{c}"));
    let mut args: Vec<&str> = vec!["log", "-p", "--no-color", "-U0", "--no-merges"];
    if let Some(c) = &count {
        args.push(c);
    } else {
        args.push("--all");
    }
    stream_log_units(repo, &args, limits, "history")
}

/// Stream `git log -p` output line-by-line into scan units under the given
/// limits. The whole patch stream is NEVER buffered: memory is bounded by
/// the retained-unit caps plus one read chunk. On any limit the child is
/// killed and reaped and the scan reports itself incomplete.
fn stream_log_units(
    repo: &Path,
    args: &[&str],
    limits: &GitLimits,
    what: &str,
) -> Result<HistoryScan> {
    let mut child = spawn_git(repo, args)?;
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut guard = ChildGuard(child);
    let (rx, _reader) = pump_stdout(stdout);
    let stderr_handle = pump_stderr(stderr);

    let mut parser = LogStreamParser::new(limits);
    let deadline = Instant::now() + limits.timeout;
    let mut streamed: u64 = 0;
    // Line assembly state over raw chunks.
    let mut line: Vec<u8> = Vec::new();
    let mut skipping_long_line = false;
    let mut incomplete_reason: Option<String> = None;

    'stream: loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            incomplete_reason = Some(format!(
                "{what} scan stopped after {:?} (git did not finish in time)",
                limits.timeout
            ));
            break 'stream;
        }
        match rx.recv_timeout(remaining) {
            Ok(Ok(chunk)) => {
                streamed += chunk.len() as u64;
                if streamed > limits.max_output_bytes {
                    incomplete_reason = Some(format!(
                        "{what} scan stopped after streaming {streamed} bytes \
                         (output limit {})",
                        limits.max_output_bytes
                    ));
                    break 'stream;
                }
                let mut rest = &chunk[..];
                while let Some(pos) = rest.iter().position(|&b| b == b'\n') {
                    if !skipping_long_line {
                        let take = pos.min(limits.max_line_bytes.saturating_sub(line.len()));
                        line.extend_from_slice(&rest[..take]);
                        let text = String::from_utf8_lossy(&line);
                        if !parser.push_line(&text) {
                            incomplete_reason = Some(format!(
                                "{what} scan stopped early: retained-content limit {} \
                                 reached",
                                limits.max_retained_bytes
                            ));
                            break 'stream;
                        }
                        line.clear();
                    } else {
                        skipping_long_line = false;
                        line.clear();
                    }
                    rest = &rest[pos + 1..];
                }
                if !skipping_long_line {
                    let take = rest
                        .len()
                        .min(limits.max_line_bytes.saturating_sub(line.len()));
                    line.extend_from_slice(&rest[..take]);
                    if line.len() >= limits.max_line_bytes {
                        // Feed the truncated prefix, then discard to newline.
                        let text = String::from_utf8_lossy(&line);
                        if !parser.push_line(&text) {
                            incomplete_reason = Some(format!(
                                "{what} scan stopped early: retained-content limit {} \
                                 reached",
                                limits.max_retained_bytes
                            ));
                            break 'stream;
                        }
                        line.clear();
                        skipping_long_line = true;
                    }
                }
            }
            Ok(Err(e)) => {
                incomplete_reason = Some(format!("{what} scan read error: {e}"));
                break 'stream;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                incomplete_reason = Some(format!(
                    "{what} scan stopped after {:?} (git produced no further output \
                     in time)",
                    limits.timeout
                ));
                break 'stream;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // EOF: flush any unterminated final line.
                if !line.is_empty() && !skipping_long_line {
                    let text = String::from_utf8_lossy(&line);
                    let _ = parser.push_line(&text);
                    line.clear();
                }
                break 'stream;
            }
        }
    }

    let complete = if incomplete_reason.is_some() {
        // Kill and reap immediately (the guard also covers panic paths).
        let _ = guard.0.kill();
        let _ = guard.0.wait();
        false
    } else {
        // EOF reached: collect the exit status within the deadline.
        loop {
            match guard.0.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        let stderr = stderr_handle.join().unwrap_or_default();
                        return Err(CoreError::InvalidInput(format!(
                            "could not read Git {what}: {}",
                            String::from_utf8_lossy(&stderr).trim()
                        )));
                    }
                    break true;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        break false;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(CoreError::Io(e)),
            }
        }
    };

    let (units, mut warnings) = parser.finish();
    if let Some(reason) = incomplete_reason {
        warnings.push(reason);
    } else if !complete {
        warnings.push(format!("{what} scan: git did not exit in time"));
    }
    // Any warning (a truncated unit included) means some content was NOT
    // examined: the scan must not present itself as complete coverage.
    let complete = complete && warnings.is_empty();
    Ok(HistoryScan {
        units,
        complete,
        warnings,
    })
}

/// Incremental parser for `git log -p -U0` output: consumes one line at a
/// time so the caller never buffers the whole patch stream. Grouping added
/// lines per (commit,file) preserves line numbers from the hunk headers so
/// findings can point at the right place. Enforces the per-unit and
/// total-retained caps; truncation is recorded as a coverage warning.
struct LogStreamParser {
    units: Vec<ScanUnit>,
    commit: String,
    file: String,
    new_line_no: usize,
    buffer: Vec<(usize, String)>,
    unit_bytes: usize,
    unit_truncated: bool,
    retained: u64,
    max_unit_bytes: usize,
    max_retained_bytes: u64,
    warnings: Vec<String>,
    suppressed_warnings: usize,
}

const MAX_COVERAGE_WARNINGS: usize = 20;

impl LogStreamParser {
    fn new(limits: &GitLimits) -> Self {
        LogStreamParser {
            units: Vec::new(),
            commit: String::new(),
            file: String::new(),
            new_line_no: 0,
            buffer: Vec::new(),
            unit_bytes: 0,
            unit_truncated: false,
            retained: 0,
            max_unit_bytes: limits.max_unit_bytes,
            max_retained_bytes: limits.max_retained_bytes,
            warnings: Vec::new(),
            suppressed_warnings: 0,
        }
    }

    fn warn(&mut self, message: String) {
        if self.warnings.len() < MAX_COVERAGE_WARNINGS {
            self.warnings.push(message);
        } else {
            self.suppressed_warnings += 1;
        }
    }

    fn flush(&mut self) {
        if self.unit_truncated {
            let label = format!(
                "commit {}:{}",
                self.commit.get(..8).unwrap_or(&self.commit),
                self.file
            );
            self.warn(format!(
                "{label}: content truncated at {} bytes; the remainder of this \
                 change was not scanned",
                self.max_unit_bytes
            ));
        }
        self.unit_truncated = false;
        self.unit_bytes = 0;
        if self.buffer.is_empty() || self.file.is_empty() {
            self.buffer.clear();
            return;
        }
        // Reconstruct a sparse text where each added line sits at its real
        // line number so scanner line numbers stay meaningful. A hunk
        // header carries the line NUMBER, which is decoupled from the
        // number of buffered lines: with `-U0` one changed line deep in a
        // huge file yields a large line number but a single entry. Cap the
        // reconstructed length so a crafted diff cannot amplify one line
        // into a multi-hundred-MB allocation; beyond the cap, real line
        // numbers no longer matter for scanning.
        const MAX_RECONSTRUCTED_LINES: usize = 200_000;
        let raw_max = self.buffer.iter().map(|(n, _)| *n).max().unwrap_or(0);
        let label = format!(
            "commit {}:{}",
            self.commit.get(..8).unwrap_or(&self.commit),
            self.file
        );
        let content = if raw_max > MAX_RECONSTRUCTED_LINES {
            // Fall back to dense packing (line numbers become approximate)
            // rather than allocating a vector sized by the line number.
            self.buffer
                .iter()
                .map(|(_, text)| text.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            let mut lines = vec![String::new(); raw_max];
            for (n, text) in self.buffer.iter() {
                if *n >= 1 && *n <= raw_max {
                    lines[*n - 1] = text.clone();
                }
            }
            lines.join("\n")
        };
        self.retained += content.len() as u64;
        self.units.push(ScanUnit { label, content });
        self.buffer.clear();
    }

    /// Feed one line. Returns false when the total-retained cap is reached
    /// and streaming must stop (the scan is then incomplete).
    fn push_line(&mut self, line: &str) -> bool {
        if let Some(rest) = line.strip_prefix("commit ") {
            self.flush();
            self.commit = rest.trim().to_string();
            self.file.clear();
        } else if let Some(rest) = line.strip_prefix("+++ b/") {
            self.flush();
            self.file = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("@@ ") {
            // @@ -a,b +c,d @@ ; take c as the starting new-file line number.
            if let Some(plus) = rest.split('+').nth(1) {
                let num: String = plus.chars().take_while(|c| c.is_ascii_digit()).collect();
                self.new_line_no = num.parse().unwrap_or(0);
            }
        } else if let Some(rest) = line.strip_prefix('+') {
            // Diff headers are `+++ b/...` (consumed above) and `+++ /dev/null`,
            // both of which have a space after `+++`. Only skip those — an
            // added *content* line like `++i;` becomes `+++i;` (no space) and
            // must still be scanned.
            if !line.starts_with("+++ ") {
                if self.unit_bytes + rest.len() > self.max_unit_bytes {
                    // Keep the unit's collected prefix; skip the rest of this
                    // unit's content (recorded as a warning at flush).
                    self.unit_truncated = true;
                    self.new_line_no += 1;
                } else {
                    self.unit_bytes += rest.len();
                    self.buffer.push((self.new_line_no, rest.to_string()));
                    self.new_line_no += 1;
                }
            }
        }
        self.retained + (self.unit_bytes as u64) <= self.max_retained_bytes
    }

    fn finish(mut self) -> (Vec<ScanUnit>, Vec<String>) {
        self.flush();
        if self.suppressed_warnings > 0 {
            let n = self.suppressed_warnings;
            self.warnings
                .push(format!("…and {n} more coverage warnings suppressed"));
        }
        (self.units, self.warnings)
    }
}

/// Parse a complete `git log -p -U0` text into scan units (uncapped; used
/// by unit tests and small in-memory inputs). Production streaming goes
/// through [`LogStreamParser`] directly.
#[cfg(test)]
fn parse_log_added_lines(log: &str) -> Vec<ScanUnit> {
    let limits = GitLimits {
        timeout: Duration::from_secs(1),
        max_output_bytes: u64::MAX,
        max_line_bytes: usize::MAX,
        max_unit_bytes: usize::MAX,
        max_retained_bytes: u64::MAX,
    };
    let mut parser = LogStreamParser::new(&limits);
    for line in log.lines() {
        if !parser.push_line(line) {
            break;
        }
    }
    parser.finish().0
}

/// Everything a full repository re-verification examines: complete history
/// plus the working tree. Collected WITHOUT any vault access so the desktop
/// app can gather it outside the vault lock.
pub struct FullRepoScan {
    pub history: HistoryScan,
    pub working_tree: Vec<ScanUnit>,
}

/// Collect a full-repository scan's content (entire history + working
/// tree). Pure git/filesystem work — no vault, no lock required.
pub fn collect_full_repo_scan(repo: &Path) -> Result<FullRepoScan> {
    let root = repo_root(repo)?;
    let history = history_added_units(&root, None)?;
    let working_tree = working_tree_units(repo)?;
    Ok(FullRepoScan {
        history,
        working_tree,
    })
}

/// Directories never worth scanning (VCS internals, dependencies, build
/// output). Their contents are skipped entirely.
const SKIP_DIRS: [&str; 10] = [
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    "vendor",
];

const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Scan units for a working-tree directory (or a single file). Skips VCS/dep
/// directories, binary files, and files larger than 5 MiB. Labels are
/// relative to `root` when possible.
pub fn working_tree_units(root: &Path) -> Result<Vec<ScanUnit>> {
    let mut units = Vec::new();
    if root.is_file() {
        if let Some(unit) = read_file_unit(root, root) {
            units.push(unit);
        }
        return Ok(units);
    }
    let walker = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            if entry.file_type().is_dir() {
                let name = entry.file_name().to_string_lossy();
                !SKIP_DIRS.contains(&name.as_ref())
            } else {
                true
            }
        });
    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(unit) = read_file_unit(root, entry.path()) {
            units.push(unit);
        }
    }
    Ok(units)
}

fn read_file_unit(root: &Path, path: &Path) -> Option<ScanUnit> {
    let label = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();
    let label = if label.is_empty() {
        path.file_name()?.to_string_lossy().to_string()
    } else {
        label
    };
    if crate::scanner::is_probably_binary(&label) {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if crate::scanner::looks_binary(&bytes) {
        return None;
    }
    Some(ScanUnit {
        label,
        content: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_added_lines_with_line_numbers() {
        let log = "\
commit abcdef1234567890
diff --git a/.env b/.env
--- /dev/null
+++ b/.env
@@ -0,0 +1,2 @@
+OPENAI_API_KEY=sk-proj-FAKE
+SAFE=1
";
        let units = parse_log_added_lines(log);
        assert_eq!(units.len(), 1);
        assert!(units[0].label.contains(".env"));
        assert!(units[0].content.contains("OPENAI_API_KEY=sk-proj-FAKE"));
        // Line 1 is the key.
        assert_eq!(
            units[0].content.lines().next().unwrap(),
            "OPENAI_API_KEY=sk-proj-FAKE"
        );
    }

    #[test]
    fn huge_line_number_does_not_allocate_a_giant_vector() {
        // A hunk header claiming line 50,000,000 with a single added line must
        // not allocate a 50M-entry vector; it falls back to dense packing.
        let log = "\
commit abcdef1234567890
diff --git a/big.txt b/big.txt
--- a/big.txt
+++ b/big.txt
@@ -49999999,0 +50000000,1 @@
+OPENAI_API_KEY=sk-proj-FAKE
";
        let units = parse_log_added_lines(log);
        assert_eq!(units.len(), 1);
        // The content is present (dense-packed) rather than sitting behind
        // 50M blank lines.
        assert!(units[0].content.contains("OPENAI_API_KEY=sk-proj-FAKE"));
        assert!(units[0].content.lines().count() < 10);
    }

    #[test]
    fn range_endpoints_must_be_hex() {
        let dir = tempfile::tempdir().unwrap();
        // Option-looking endpoints are refused before git ever runs.
        for (old, new) in [("--output=/tmp/x", "HEAD"), ("abc123", "..evil")] {
            match range_added_units(dir.path(), old, new) {
                Err(CoreError::InvalidInput(_)) => {}
                _ => panic!("expected InvalidInput for {old:?}..{new:?}, got Ok/other"),
            }
        }
    }

    #[test]
    fn keeps_added_content_lines_starting_with_plus_plus() {
        // A `++i;` content line renders as `+++i;` in the diff and must not be
        // mistaken for a `+++ b/...` header.
        let log = "\
commit abcdef1234567890
diff --git a/main.c b/main.c
--- /dev/null
+++ b/main.c
@@ -0,0 +1,2 @@
+++i;
+int x = 1;
";
        let units = parse_log_added_lines(log);
        assert_eq!(units.len(), 1);
        assert!(
            units[0].content.contains("++i;"),
            "the ++i; line must be scanned"
        );
        assert!(units[0].content.contains("int x = 1;"));
    }
}
