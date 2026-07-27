//! Lossless `.env` file parsing and serialization.
//!
//! Parsing is purely textual — content is never executed, interpolated, or
//! shell-expanded. The document model preserves comments, blank lines,
//! ordering, quoting style, `export` prefixes, and the file's dominant line
//! ending, so an unmodified document round-trips byte-for-byte (files with
//! MIXED line endings are normalized to the dominant one). Values are
//! held in [`SecretString`] (redacted `Debug`/`Display`/`Serialize`, zeroized
//! on drop); previews expose only masked values.

use crate::model::mask_value;
use crate::secret::SecretString;
use serde::Serialize;
use std::collections::HashMap;

/// The substring that identifies a comment line as a Tethra gateway
/// ownership marker. Ownership is expressed as a COMMENT rather than a
/// variable because `tethra run` scrubs `TETHRA_*` names from child
/// environments (KNOWN_CONFLICTS C10) and a comment survives every dotenv
/// loader untouched. Shared by the `.env` link writer (which composes the
/// full marker text) and `.env.example` generation (which skips marked keys).
pub const GATEWAY_MARKER_TAG: &str = "tethra-gateway";

/// The line ending used when rendering new or modified lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Newline {
    Lf,
    CrLf,
}

impl Newline {
    fn as_str(self) -> &'static str {
        match self {
            Newline::Lf => "\n",
            Newline::CrLf => "\r\n",
        }
    }
}

/// How a value was quoted in the source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Quoting {
    Bare,
    Single,
    Double,
}

/// One `KEY=value` entry.
#[derive(Debug, Clone)]
pub struct EnvEntry {
    pub key: String,
    /// The decoded value (quotes stripped, double-quote escapes decoded).
    pub value: SecretString,
    pub quoting: Quoting,
    /// The line began with `export `.
    pub export: bool,
    /// Inline ` # comment` following an unquoted or quoted value.
    pub inline_comment: Option<String>,
    /// The exact source line (no newline; contains the value, so it is held
    /// in a redacting `SecretString`). Empty for entries added
    /// programmatically; regenerated whenever the entry is modified.
    raw: SecretString,
    /// 1-based source line number; 0 for added entries.
    pub line: usize,
}

/// One line of the document.
#[derive(Debug, Clone)]
pub enum EnvLine {
    /// Whitespace-only line, preserved verbatim.
    Blank(String),
    /// Full-line comment (`# ...`), preserved verbatim.
    Comment(String),
    Entry(EnvEntry),
    /// A line that could not be parsed. Preserved verbatim on rendering,
    /// reported as a problem. `raw` may contain secret material, so it is
    /// held in a redacting `SecretString`; only the reason is displayed.
    Malformed {
        raw: SecretString,
        line: usize,
        reason: String,
    },
}

/// A parse problem safe to display (no values).
#[derive(Debug, Clone, Serialize)]
pub struct EnvProblem {
    pub line: usize,
    pub kind: EnvProblemKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvProblemKind {
    Malformed,
    DuplicateKey,
}

/// A parsed `.env` document that can be edited and re-rendered.
#[derive(Debug, Clone)]
pub struct EnvDocument {
    pub lines: Vec<EnvLine>,
    pub newline: Newline,
    trailing_newline: bool,
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false)
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Decode a double-quoted value's escapes (`\"`, `\\`, `\n`, `\r`, `\t`).
/// Unknown escapes are kept literally (backslash + char).
fn decode_double(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn encode_double(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// Render an entry to a source line.
fn render_entry(entry: &EnvEntry) -> String {
    let mut out = String::new();
    if entry.export {
        out.push_str("export ");
    }
    out.push_str(&entry.key);
    out.push('=');
    let value = entry.value.expose();
    match entry.quoting {
        // Control characters (a multi-line value, say) cannot survive
        // single quotes; fall through to double quoting, which escapes.
        Quoting::Single if !value.contains('\'') && !value.chars().any(|c| c.is_control()) => {
            out.push('\'');
            out.push_str(value);
            out.push('\'');
        }
        // A value that cannot be represented bare or single-quoted falls
        // back to double quoting.
        Quoting::Bare
            if !value.is_empty()
                && !value.starts_with('\'')
                && !value.contains(|c: char| {
                    c.is_whitespace() || c == '#' || c == '"' || c.is_control()
                })
                && value.trim() == value =>
        {
            out.push_str(value);
        }
        _ => {
            out.push('"');
            out.push_str(&encode_double(value));
            out.push('"');
        }
    }
    if let Some(comment) = &entry.inline_comment {
        out.push(' ');
        out.push_str(comment);
    }
    out
}

impl EnvEntry {
    /// Create a new entry (used for additions); quoting is chosen on render.
    pub fn new(key: &str, value: SecretString) -> Self {
        let mut entry = EnvEntry {
            key: key.to_string(),
            value,
            quoting: Quoting::Bare,
            export: false,
            inline_comment: None,
            raw: SecretString::new(String::new()),
            line: 0,
        };
        entry.raw = SecretString::new(render_entry(&entry));
        entry
    }

    /// Replace the value, re-rendering the source line but preserving the
    /// quoting style, `export` prefix, and inline comment.
    pub fn set_value(&mut self, value: SecretString) {
        self.value = value;
        self.raw = SecretString::new(render_entry(self));
    }

    /// Masked value safe for display.
    pub fn masked(&self) -> String {
        mask_value(self.value.expose())
    }
}

/// Parse a single line. Returns `Ok(None)` for blank/comment lines handled by
/// the caller.
fn parse_entry(line: &str, line_no: usize) -> Result<EnvEntry, String> {
    let trimmed = line.trim_start();
    let (export, rest) = match trimmed.strip_prefix("export ") {
        Some(rest) => (true, rest.trim_start()),
        None => (false, trimmed),
    };
    let eq = rest.find('=').ok_or_else(|| "no '=' found".to_string())?;
    let key = rest[..eq].trim_end().to_string();
    if !valid_key(&key) {
        return Err(format!("'{key}' is not a valid variable name"));
    }
    let value_part = &rest[eq + 1..];
    let value_trimmed = value_part.trim_start();

    let (value, quoting, inline_comment) = if let Some(after) = value_trimmed.strip_prefix('\'') {
        let close = after.find('\'').ok_or("unterminated single quote")?;
        let value = after[..close].to_string();
        let tail = after[close + 1..].trim();
        let comment = parse_tail_comment(tail)?;
        (value, Quoting::Single, comment)
    } else if let Some(after) = value_trimmed.strip_prefix('"') {
        let close = find_closing_double(after).ok_or("unterminated double quote")?;
        let value = decode_double(&after[..close]);
        let tail = after[close + 1..].trim();
        let comment = parse_tail_comment(tail)?;
        (value, Quoting::Double, comment)
    } else {
        // Bare value: runs to an inline ` #` (whitespace before '#') or EOL.
        let mut value_end = value_trimmed.len();
        let mut comment = None;
        let bytes = value_trimmed.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            if *b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
                value_end = i;
                comment = Some(value_trimmed[i..].trim_end().to_string());
                break;
            }
        }
        (
            value_trimmed[..value_end].trim().to_string(),
            Quoting::Bare,
            comment,
        )
    };

    Ok(EnvEntry {
        key,
        value: SecretString::new(value),
        quoting,
        export,
        inline_comment,
        raw: SecretString::new(line.to_string()),
        line: line_no,
    })
}

fn parse_tail_comment(tail: &str) -> Result<Option<String>, String> {
    if tail.is_empty() {
        Ok(None)
    } else if tail.starts_with('#') {
        Ok(Some(tail.to_string()))
    } else {
        Err("unexpected content after closing quote".to_string())
    }
}

/// Find the closing unescaped double quote.
fn find_closing_double(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return Some(i),
            _ => {}
        }
    }
    None
}

impl EnvDocument {
    /// Parse file content. Never fails: unparseable lines become
    /// [`EnvLine::Malformed`] and are reported by [`EnvDocument::problems`].
    pub fn parse(content: &str) -> Self {
        let crlf = content.matches("\r\n").count();
        let lf_total = content.matches('\n').count();
        let newline = if crlf > 0 && crlf * 2 >= lf_total {
            Newline::CrLf
        } else {
            Newline::Lf
        };
        let trailing_newline = content.is_empty() || content.ends_with('\n');

        let mut fragments: Vec<&str> = content.split('\n').collect();
        // The fragment after a trailing newline is empty and is not a line.
        if trailing_newline && fragments.last() == Some(&"") {
            fragments.pop();
        }
        let mut lines = Vec::new();
        for (idx, raw_line) in fragments.into_iter().enumerate() {
            let line_no = idx + 1;
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            let trimmed = line.trim();
            if trimmed.is_empty() {
                lines.push(EnvLine::Blank(line.to_string()));
            } else if trimmed.starts_with('#') {
                lines.push(EnvLine::Comment(line.to_string()));
            } else {
                match parse_entry(line, line_no) {
                    Ok(entry) => lines.push(EnvLine::Entry(entry)),
                    Err(reason) => lines.push(EnvLine::Malformed {
                        raw: SecretString::new(line.to_string()),
                        line: line_no,
                        reason,
                    }),
                }
            }
        }
        EnvDocument {
            lines,
            newline,
            trailing_newline,
        }
    }

    /// Render the document. Unmodified lines are emitted verbatim.
    pub fn render(&self) -> String {
        let nl = self.newline.as_str();
        let mut out = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                out.push_str(nl);
            }
            match line {
                EnvLine::Blank(raw) | EnvLine::Comment(raw) => out.push_str(raw),
                EnvLine::Entry(entry) => out.push_str(entry.raw.expose()),
                EnvLine::Malformed { raw, .. } => out.push_str(raw.expose()),
            }
        }
        if self.trailing_newline && !self.lines.is_empty() {
            out.push_str(nl);
        }
        out
    }

    /// All entries in order.
    pub fn entries(&self) -> impl Iterator<Item = &EnvEntry> {
        self.lines.iter().filter_map(|l| match l {
            EnvLine::Entry(e) => Some(e),
            _ => None,
        })
    }

    /// The entry for `key` (the LAST occurrence wins, matching dotenv
    /// loaders' common behavior of later lines overriding earlier ones).
    pub fn get(&self, key: &str) -> Option<&EnvEntry> {
        self.entries().filter(|e| e.key == key).last()
    }

    /// Set `key` to `value`: updates every existing occurrence in place
    /// (preserving quoting/comments) or appends a new entry.
    pub fn set(&mut self, key: &str, value: SecretString) {
        let mut found = false;
        for line in &mut self.lines {
            if let EnvLine::Entry(entry) = line {
                if entry.key == key {
                    entry.set_value(value.clone());
                    found = true;
                }
            }
        }
        if !found {
            self.lines.push(EnvLine::Entry(EnvEntry::new(key, value)));
        }
    }

    /// Restore each occurrence of `key` to its own recorded value, in file
    /// order. [`set`] deliberately writes ONE value to every occurrence, which
    /// is right for linking (all occurrences must point at the gateway) and
    /// wrong for restoring (each occurrence had its own prior value). Extra
    /// occurrences beyond `values` keep the last supplied value, so the
    /// method is total even if the file gained a duplicate after linking.
    pub fn set_each_occurrence(&mut self, key: &str, values: &[String]) {
        if values.is_empty() {
            return;
        }
        let mut i = 0usize;
        for line in &mut self.lines {
            if let EnvLine::Entry(entry) = line {
                if entry.key == key {
                    let v = values.get(i).unwrap_or(&values[values.len() - 1]);
                    entry.set_value(SecretString::new(v.clone()));
                    i += 1;
                }
            }
        }
    }

    /// Remove every occurrence of `key`. Returns whether anything was removed.
    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.lines.len();
        self.lines.retain(|l| match l {
            EnvLine::Entry(e) => e.key != key,
            _ => true,
        });
        self.lines.len() != before
    }

    /// Set `key` to `value` and keep exactly one ownership marker comment
    /// directly above its first occurrence (TEST_PLAN §10). The comment must
    /// contain [`GATEWAY_MARKER_TAG`]; a stale marker already there is
    /// replaced, an identical one is left alone, and any other line above the
    /// entry is preserved — the marker is inserted, never overwritten onto
    /// user content. Ownership is a comment, never a variable, because
    /// `tethra run` scrubs `TETHRA_*` names from child environments
    /// (KNOWN_CONFLICTS C10).
    pub fn set_with_comment(&mut self, key: &str, value: SecretString, comment: &str) {
        debug_assert!(
            comment.contains(GATEWAY_MARKER_TAG),
            "marker comments must carry the ownership tag"
        );
        self.set(key, value);
        let rendered = if comment.trim_start().starts_with('#') {
            comment.to_string()
        } else {
            format!("# {comment}")
        };
        let idx = self
            .lines
            .iter()
            .position(|l| matches!(l, EnvLine::Entry(e) if e.key == key))
            .expect("set() guarantees the entry exists");
        if idx > 0 {
            if let EnvLine::Comment(existing) = &self.lines[idx - 1] {
                if existing.trim() == rendered.trim() {
                    return;
                }
                if existing.contains(GATEWAY_MARKER_TAG) {
                    self.lines[idx - 1] = EnvLine::Comment(rendered);
                    return;
                }
            }
        }
        self.lines.insert(idx, EnvLine::Comment(rendered));
    }

    /// Remove every occurrence of `key` AND any marker comment directly above
    /// one. Returns whether anything was removed. Non-marker comments are
    /// never touched.
    pub fn remove_with_comment(&mut self, key: &str) -> bool {
        let mut removed = false;
        while let Some(idx) = self
            .lines
            .iter()
            .position(|l| matches!(l, EnvLine::Entry(e) if e.key == key))
        {
            self.lines.remove(idx);
            removed = true;
            if idx > 0 {
                if let EnvLine::Comment(c) = &self.lines[idx - 1] {
                    if c.contains(GATEWAY_MARKER_TAG) {
                        self.lines.remove(idx - 1);
                    }
                }
            }
        }
        removed
    }

    /// Remove the marker comment directly above the first occurrence of
    /// `key`, leaving the entry itself in place (unlink restores a prior
    /// value but drops Tethra's ownership claim). Returns whether a marker
    /// was removed.
    pub fn remove_marker_above(&mut self, key: &str) -> bool {
        let Some(idx) = self
            .lines
            .iter()
            .position(|l| matches!(l, EnvLine::Entry(e) if e.key == key))
        else {
            return false;
        };
        if idx > 0 {
            if let EnvLine::Comment(c) = &self.lines[idx - 1] {
                if c.contains(GATEWAY_MARKER_TAG) {
                    self.lines.remove(idx - 1);
                    return true;
                }
            }
        }
        false
    }

    /// Keys whose first occurrence sits directly under a gateway marker
    /// comment — i.e. lines Tethra wrote and owns. `.env.example` generation
    /// skips these (a gateway base URL is machine-local wiring, not a
    /// variable collaborators should copy).
    pub fn keys_with_gateway_marker(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (i, line) in self.lines.iter().enumerate() {
            if let EnvLine::Entry(e) = line {
                if i > 0 && !out.contains(&e.key) {
                    if let EnvLine::Comment(c) = &self.lines[i - 1] {
                        if c.contains(GATEWAY_MARKER_TAG) {
                            out.push(e.key.clone());
                        }
                    }
                }
            }
        }
        out
    }

    /// Parse problems: malformed lines and duplicate keys.
    pub fn problems(&self) -> Vec<EnvProblem> {
        let mut out = Vec::new();
        for line in &self.lines {
            if let EnvLine::Malformed { line, reason, .. } = line {
                out.push(EnvProblem {
                    line: *line,
                    kind: EnvProblemKind::Malformed,
                    detail: reason.clone(),
                });
            }
        }
        let mut seen: HashMap<&str, usize> = HashMap::new();
        for entry in self.entries() {
            if let Some(first) = seen.get(entry.key.as_str()) {
                out.push(EnvProblem {
                    line: entry.line,
                    kind: EnvProblemKind::DuplicateKey,
                    detail: format!(
                        "'{}' is also defined on line {first}; the later value usually wins",
                        entry.key
                    ),
                });
            } else {
                seen.insert(&entry.key, entry.line);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# app config\nAPI_KEY=abc123\n\nexport DB_URL='postgres://u:p@localhost/db'\nGREETING=\"hello \\\"world\\\"\" # inline\nEMPTY=\nSPACED = padded value  \n";

    #[test]
    fn round_trips_unmodified_content() {
        let doc = EnvDocument::parse(SAMPLE);
        assert_eq!(doc.render(), SAMPLE);
    }

    #[test]
    fn round_trips_crlf_and_no_trailing_newline() {
        let crlf = "A=1\r\n# c\r\nB=2";
        let doc = EnvDocument::parse(crlf);
        assert_eq!(doc.newline, Newline::CrLf);
        assert_eq!(doc.render(), crlf);
    }

    #[test]
    fn parses_values_quoting_and_comments() {
        let doc = EnvDocument::parse(SAMPLE);
        assert_eq!(doc.get("API_KEY").unwrap().value.expose(), "abc123");
        let db = doc.get("DB_URL").unwrap();
        assert_eq!(db.value.expose(), "postgres://u:p@localhost/db");
        assert!(db.export);
        assert_eq!(db.quoting, Quoting::Single);
        let greeting = doc.get("GREETING").unwrap();
        assert_eq!(greeting.value.expose(), "hello \"world\"");
        assert_eq!(greeting.inline_comment.as_deref(), Some("# inline"));
        assert_eq!(doc.get("EMPTY").unwrap().value.expose(), "");
        assert_eq!(doc.get("SPACED").unwrap().value.expose(), "padded value");
    }

    #[test]
    fn bare_value_hash_needs_preceding_whitespace() {
        let doc = EnvDocument::parse("TAG=abc#notcomment\nOTHER=x # real\n");
        assert_eq!(doc.get("TAG").unwrap().value.expose(), "abc#notcomment");
        assert_eq!(doc.get("OTHER").unwrap().value.expose(), "x");
    }

    #[test]
    fn reports_malformed_and_duplicates() {
        let doc = EnvDocument::parse("GOOD=1\nnot a line\n1BAD=x\nGOOD=2\nUNTERM=\"oops\n");
        let problems = doc.problems();
        let kinds: Vec<_> = problems.iter().map(|p| (p.line, p.kind)).collect();
        assert!(kinds.contains(&(2, EnvProblemKind::Malformed)));
        assert!(kinds.contains(&(3, EnvProblemKind::Malformed)));
        assert!(kinds.contains(&(4, EnvProblemKind::DuplicateKey)));
        assert!(kinds.contains(&(5, EnvProblemKind::Malformed)));
        // Later duplicate wins on read.
        assert_eq!(doc.get("GOOD").unwrap().value.expose(), "2");
    }

    #[test]
    fn malformed_lines_round_trip_verbatim() {
        let content = "GOOD=1\nnot a line\nGOOD2=2\n";
        let doc = EnvDocument::parse(content);
        assert_eq!(doc.render(), content);
    }

    #[test]
    fn set_preserves_quoting_and_comment() {
        let mut doc = EnvDocument::parse("KEY=\"old\" # keep me\n");
        doc.set("KEY", SecretString::from("new"));
        assert_eq!(doc.render(), "KEY=\"new\" # keep me\n");
    }

    #[test]
    fn set_appends_missing_key_and_remove_deletes() {
        let mut doc = EnvDocument::parse("A=1\n");
        doc.set("B", SecretString::from("two"));
        assert_eq!(doc.render(), "A=1\nB=two\n");
        assert!(doc.remove("A"));
        assert!(!doc.remove("A"));
        assert_eq!(doc.render(), "B=two\n");
    }

    #[test]
    fn set_updates_every_duplicate_occurrence() {
        let mut doc = EnvDocument::parse("K=1\nK=2\n");
        doc.set("K", SecretString::from("x"));
        assert_eq!(doc.render(), "K=x\nK=x\n");
    }

    #[test]
    fn values_needing_quotes_are_double_quoted_on_render() {
        let mut doc = EnvDocument::parse("");
        doc.set("MSG", SecretString::from("two words # hash"));
        doc.set("QUOTE", SecretString::from("it\"s"));
        let rendered = doc.render();
        assert!(rendered.contains("MSG=\"two words # hash\""));
        assert!(rendered.contains("QUOTE=\"it\\\"s\""));
    }

    #[test]
    fn parsing_never_executes_or_interpolates() {
        let doc = EnvDocument::parse("CMD=$(rm -rf /)\nREF=$HOME/x\nTICK=`whoami`\n");
        assert_eq!(doc.get("CMD").unwrap().value.expose(), "$(rm -rf /)");
        assert_eq!(doc.get("REF").unwrap().value.expose(), "$HOME/x");
        assert_eq!(doc.get("TICK").unwrap().value.expose(), "`whoami`");
    }

    #[test]
    fn empty_document_round_trips() {
        let doc = EnvDocument::parse("");
        assert_eq!(doc.render(), "");
    }

    #[test]
    fn set_value_round_trips_hostile_values_regardless_of_prior_quoting() {
        // A multi-line value replacing a single-quoted entry must not
        // corrupt the file (unterminated quote + value tail on its own line).
        let mut doc = EnvDocument::parse("KEY='old'\n");
        doc.set("KEY", SecretString::from("line1\nline2=looks-like-entry"));
        let rendered = doc.render();
        let reparsed = EnvDocument::parse(&rendered);
        assert_eq!(
            reparsed.get("KEY").unwrap().value.expose(),
            "line1\nline2=looks-like-entry"
        );
        assert!(
            reparsed.get("line2").is_none(),
            "no phantom entry: {rendered}"
        );

        // A bare value starting with a single quote must not be emitted bare
        // (it would re-parse with the quotes stripped or vanish).
        let mut doc = EnvDocument::parse("");
        doc.set("A", SecretString::from("'til-dawn"));
        doc.set("B", SecretString::from("'wrapped'"));
        let reparsed = EnvDocument::parse(&doc.render());
        assert_eq!(reparsed.get("A").unwrap().value.expose(), "'til-dawn");
        assert_eq!(reparsed.get("B").unwrap().value.expose(), "'wrapped'");
    }

    #[test]
    fn entry_debug_never_shows_value() {
        let doc = EnvDocument::parse("SECRET_KEY=sk-test-FAKE-abcdef1234567890\n");
        let debugged = format!("{:?}", doc.get("SECRET_KEY").unwrap());
        assert!(!debugged.contains("abcdef1234567890"));
    }

    const MARKER: &str =
        "tethra-gateway route: openai (project: app) — remove this line if 127.0.0.1 \
         refuses connections, or run: tethra gateway status";

    #[test]
    fn set_with_comment_inserts_one_marker_and_is_idempotent() {
        let mut doc = EnvDocument::parse("EXISTING=1\n");
        doc.set_with_comment(
            "OPENAI_BASE_URL",
            SecretString::from("http://127.0.0.1:49723/p/abc/openai/v1"),
            MARKER,
        );
        let first = doc.render();
        assert!(first.contains(&format!("# {MARKER}\nOPENAI_BASE_URL=")));

        // Applying the identical link again must not duplicate the marker.
        doc.set_with_comment(
            "OPENAI_BASE_URL",
            SecretString::from("http://127.0.0.1:49723/p/abc/openai/v1"),
            MARKER,
        );
        assert_eq!(doc.render(), first, "idempotent re-link");
        assert_eq!(doc.render().matches(GATEWAY_MARKER_TAG).count(), 1);
    }

    #[test]
    fn set_with_comment_replaces_a_stale_marker_but_never_user_comments() {
        // A stale marker (old port / renamed project) is replaced in place.
        let mut doc =
            EnvDocument::parse("# tethra-gateway route: openai (project: old)\nOPENAI_BASE_URL=http://127.0.0.1:1/p/x/openai/v1\n");
        doc.set_with_comment("OPENAI_BASE_URL", SecretString::from("new"), MARKER);
        let rendered = doc.render();
        assert_eq!(rendered.matches(GATEWAY_MARKER_TAG).count(), 1);
        assert!(rendered.contains("project: app"));

        // A user's own comment above the key is preserved, marker inserted
        // between it and the entry.
        let mut doc = EnvDocument::parse("# my own note\nOPENAI_BASE_URL=x\n");
        doc.set_with_comment("OPENAI_BASE_URL", SecretString::from("new"), MARKER);
        let rendered = doc.render();
        assert!(rendered.contains("# my own note\n"));
        assert!(rendered.contains(&format!("# {MARKER}\nOPENAI_BASE_URL=")));
    }

    #[test]
    fn remove_with_comment_takes_the_marker_but_spares_user_comments() {
        let mut doc = EnvDocument::parse(
            "# my own note\n# tethra-gateway route: openai (project: app)\nOPENAI_BASE_URL=x\nOTHER=1\n",
        );
        assert!(doc.remove_with_comment("OPENAI_BASE_URL"));
        let rendered = doc.render();
        assert_eq!(rendered, "# my own note\nOTHER=1\n");
        assert!(
            !doc.remove_with_comment("OPENAI_BASE_URL"),
            "second removal is a no-op"
        );
    }

    #[test]
    fn remove_marker_above_leaves_the_entry_for_prior_value_restore() {
        let mut doc = EnvDocument::parse(
            "# tethra-gateway route: openai (project: app)\nOPENAI_BASE_URL=https://corp-proxy.example/v1\n",
        );
        assert!(doc.remove_marker_above("OPENAI_BASE_URL"));
        assert_eq!(
            doc.render(),
            "OPENAI_BASE_URL=https://corp-proxy.example/v1\n"
        );
        assert!(!doc.remove_marker_above("OPENAI_BASE_URL"));
    }

    #[test]
    fn keys_with_gateway_marker_reports_only_marked_keys() {
        let doc = EnvDocument::parse(
            "OPENAI_API_KEY=sk-test-FAKE\n# tethra-gateway route: openai (project: app)\nOPENAI_BASE_URL=x\n# unrelated comment\nOTHER=1\n",
        );
        assert_eq!(doc.keys_with_gateway_marker(), vec!["OPENAI_BASE_URL"]);
    }

    #[test]
    fn set_with_comment_preserves_crlf_and_surrounding_content() {
        let mut doc = EnvDocument::parse("A=1\r\n\r\n# note\r\nB=2\r\n");
        doc.set_with_comment("OPENAI_BASE_URL", SecretString::from("v"), MARKER);
        let rendered = doc.render();
        assert!(rendered.starts_with("A=1\r\n\r\n# note\r\nB=2\r\n"));
        assert!(rendered.ends_with(&format!("# {MARKER}\r\nOPENAI_BASE_URL=v\r\n")));
    }
}
