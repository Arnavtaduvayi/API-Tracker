//! Bounded, best-effort usage extraction (ADR 0019 D6).
//!
//! This is the one place in Tethra that inspects response BYTES. It is
//! constrained on every axis:
//!
//! - **Fixed allowlist out.** Model identifier plus token counts. Nothing
//!   else is ever extracted, whatever the body contains. The record type has
//!   no body-capable field.
//! - **Bounded state.** An SSE stream is parsed incrementally holding at most
//!   one capped event plus one capped line; an oversized event is discarded
//!   WHOLESALE and counted, never partially parsed. Non-streamed JSON uses a
//!   capped tail window. No code path accumulates a whole body.
//! - **Provider-scoped.** Extractors run only for a response shape the
//!   route's provider declares. Unknown shapes parse nothing.
//! - **Never authoritative.** A missing number is recorded as a state
//!   (`absent`, `unsupported_shape`, ...), never as a fabricated zero.
//! - **Silent to traffic.** Extraction cannot fail a request, cannot slow the
//!   relay materially, and cannot mutate a relayed byte: the tap only ever
//!   sees a copy of bytes already written to the client.

use crate::forward::BodyTap;
use crate::record::{UsageObservation, UsageState};

/// Max bytes held for one SSE event (an event larger than this is dropped
/// wholesale and counted).
pub const MAX_EVENT: usize = 128 * 1024;
/// Max bytes held for one line while assembling an event.
pub const MAX_LINE: usize = MAX_EVENT;
/// Tail window for non-streamed JSON: usage objects sit at the END of
/// OpenAI/Anthropic response bodies (OPEN_DECISIONS O4).
pub const JSON_TAIL_WINDOW: usize = 64 * 1024;
/// Model strings are the first free-form body-derived value in the schema, so
/// they are capped and charset-filtered before they can be persisted.
pub const MAX_MODEL_LEN: usize = 128;

/// Which provider response shape to parse. Anything else parses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    OpenAi,
    Anthropic,
}

impl Shape {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "openai" => Some(Shape::OpenAi),
            "anthropic" => Some(Shape::Anthropic),
            _ => None,
        }
    }
}

/// Accept a model string only if it is short and drawn from a conservative
/// charset. A violation stores NULL plus a counter — NEVER a truncated
/// attacker-controlled string, which would be a body-content smuggling path
/// into the database.
pub fn sanitize_model(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_MODEL_LEN {
        return None;
    }
    let ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '@' | '/' | '-'));
    ok.then(|| raw.to_string())
}

/// Accumulated, allowlisted numbers. Never overwrites a populated field with
/// a null: OpenAI streaming yields usage only in a terminal chunk, and
/// Anthropic splits it across `message_start` and `message_delta`.
#[derive(Debug, Default, Clone)]
struct Acc {
    model: Option<String>,
    model_rejected: bool,
    /// The provider's BASE input count, before any cache components are
    /// folded in. Kept separate so a repeated frame cannot double-count.
    input: Option<u64>,
    output: Option<u64>,
    total: Option<u64>,
    /// Cache-read input tokens, tracked in their own field.
    cache_read: Option<u64>,
    /// Cache-creation input tokens, likewise.
    cache_creation: Option<u64>,
    saw_usage: bool,
    malformed: bool,
}

impl Acc {
    fn set_model(&mut self, raw: &str) {
        if self.model.is_some() {
            return;
        }
        match sanitize_model(raw) {
            Some(m) => self.model = Some(m),
            None => self.model_rejected = true,
        }
    }
    fn set_max(field: &mut Option<u64>, v: Option<u64>) {
        if let Some(v) = v {
            *field = Some(field.map_or(v, |cur| cur.max(v)));
        }
    }
}

fn u64_of(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
}

/// Parse one JSON document for the provider's usage shape.
fn absorb_json(acc: &mut Acc, shape: Shape, v: &serde_json::Value) {
    if let Some(m) = v.get("model").and_then(|m| m.as_str()) {
        acc.set_model(m);
    }
    match shape {
        Shape::OpenAi => {
            // Chat/completions and responses: a flat `usage` object. Present
            // in streaming ONLY when the caller set stream_options
            // .include_usage — which the gateway must NOT inject, since the
            // request body is streamed, never rewritten.
            if let Some(u) = v.get("usage").filter(|u| !u.is_null()) {
                acc.saw_usage = true;
                Acc::set_max(&mut acc.input, u.get("prompt_tokens").and_then(u64_of));
                Acc::set_max(&mut acc.input, u.get("input_tokens").and_then(u64_of));
                Acc::set_max(&mut acc.output, u.get("completion_tokens").and_then(u64_of));
                Acc::set_max(&mut acc.output, u.get("output_tokens").and_then(u64_of));
                Acc::set_max(&mut acc.total, u.get("total_tokens").and_then(u64_of));
                let cached = u
                    .get("prompt_tokens_details")
                    .and_then(|d| d.get("cached_tokens"))
                    .and_then(u64_of)
                    .or_else(|| {
                        u.get("input_tokens_details")
                            .and_then(|d| d.get("cached_tokens"))
                            .and_then(u64_of)
                    });
                Acc::set_max(&mut acc.cache_read, cached);
            }
        }
        Shape::Anthropic => {
            // The REAL Anthropic SSE shape: `message_start` carries a nested
            // message.usage with input + cache counts, `message_delta`
            // carries output. They must ACCUMULATE, and a later null must
            // never clear an earlier number.
            if let Some(m) = v
                .get("message")
                .and_then(|m| m.get("model"))
                .and_then(|m| m.as_str())
            {
                acc.set_model(m);
            }
            let usage = v
                .get("usage")
                .filter(|u| !u.is_null())
                .or_else(|| v.get("message").and_then(|m| m.get("usage")))
                .filter(|u| !u.is_null());
            if let Some(u) = usage {
                acc.saw_usage = true;
                // EVERY field uses the idempotent set_max, cache components
                // included: Anthropic's `message_delta` repeats the
                // CUMULATIVE input and cache counts, not just the output, so
                // adding them per frame double-counted every prompt-cached
                // request. The components are summed ONCE, in
                // `observation()`.
                Acc::set_max(&mut acc.input, u.get("input_tokens").and_then(u64_of));
                Acc::set_max(&mut acc.output, u.get("output_tokens").and_then(u64_of));
                Acc::set_max(
                    &mut acc.cache_read,
                    u.get("cache_read_input_tokens").and_then(u64_of),
                );
                Acc::set_max(
                    &mut acc.cache_creation,
                    u.get("cache_creation_input_tokens").and_then(u64_of),
                );
            }
        }
    }
}

/// The streaming extractor. Feed it response bytes as they relay; it never
/// sees the stream again and never holds more than its caps.
pub struct UsageExtractor {
    shape: Shape,
    streaming: bool,
    /// Set when the response is compressed or otherwise unscannable.
    unsupported: bool,
    line: Vec<u8>,
    event: Vec<u8>,
    oversized: bool,
    dropped_events: u64,
    /// Rolling tail window for non-streamed JSON.
    tail: Vec<u8>,
    acc: Acc,
    finished: bool,
}

impl UsageExtractor {
    /// `streaming` selects the SSE parser; `unsupported` marks a response the
    /// gateway declines to scan (compressed, unknown encoding).
    pub fn new(shape: Shape, streaming: bool, unsupported: bool) -> Self {
        Self {
            shape,
            streaming,
            unsupported,
            line: Vec::new(),
            event: Vec::new(),
            oversized: false,
            dropped_events: 0,
            tail: Vec::new(),
            acc: Acc::default(),
            finished: false,
        }
    }

    /// Peak transient memory this extractor may hold, for the bounds proof.
    pub fn bound(&self) -> usize {
        if self.streaming {
            MAX_LINE + MAX_EVENT
        } else {
            JSON_TAIL_WINDOW
        }
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    fn on_line(&mut self, line: &[u8]) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            // Event boundary.
            let data = std::mem::take(&mut self.event);
            let oversized = std::mem::replace(&mut self.oversized, false);
            if oversized {
                self.dropped_events += 1;
            } else if !data.is_empty() {
                self.on_event(&data);
            }
            return;
        }
        if self.oversized {
            return; // still skipping a poisoned event
        }
        if let Some(rest) = line.strip_prefix(b"data:") {
            let rest = rest.strip_prefix(b" ").unwrap_or(rest);
            if self.event.len() + rest.len() + 1 > MAX_EVENT {
                self.oversized = true;
                self.event.clear();
                self.event.shrink_to_fit();
                return;
            }
            if !self.event.is_empty() {
                self.event.push(b'\n');
            }
            self.event.extend_from_slice(rest);
        }
        // `event:`, `id:`, `retry:` and comments are ignored entirely.
    }

    fn on_event(&mut self, data: &[u8]) {
        if data == b"[DONE]" {
            return;
        }
        match serde_json::from_slice::<serde_json::Value>(data) {
            Ok(v) => absorb_json(&mut self.acc, self.shape, &v),
            // A malformed event is noted, never logged (it is body content).
            Err(_) => self.acc.malformed = true,
        }
    }

    /// Parse the buffered tail of a non-streamed JSON body.
    fn finish_json(&mut self) {
        if self.tail.is_empty() {
            return;
        }
        // Whole document first (the common case: the body fit in the window).
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&self.tail) {
            absorb_json(&mut self.acc, self.shape, &v);
            return;
        }
        // Truncated head: scan the window for the last `"usage"` object and
        // parse only that object, bounded by brace matching. Nothing outside
        // the object is inspected or retained.
        if let Some(obj) = last_usage_object(&self.tail) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&obj) {
                let wrapper = serde_json::json!({ "usage": v });
                absorb_json(&mut self.acc, self.shape, &wrapper);
                return;
            }
        }
        self.acc.malformed = true;
    }

    /// The extracted, allowlisted result.
    pub fn observation(&mut self) -> UsageObservation {
        if !self.finished {
            self.finished = true;
            if !self.unsupported && !self.streaming {
                self.finish_json();
            }
        }
        let state = if self.unsupported {
            UsageState::UnsupportedShape
        } else if self.acc.saw_usage {
            UsageState::Extracted
        } else if self.dropped_events > 0 {
            UsageState::OversizedDropped
        } else if self.acc.malformed {
            UsageState::Malformed
        } else {
            UsageState::Absent
        };
        // Cache components are summed into the input total exactly once,
        // here, from idempotently-tracked fields. Anthropic reports
        // cache-read and cache-creation SEPARATELY from `input_tokens`, and
        // both are input tokens the caller was billed for; OpenAI reports
        // cached tokens as a SUBSET of `prompt_tokens`, so folding them in
        // there would double-count. The provider shape decides which.
        let input_tokens = match self.shape {
            Shape::Anthropic => {
                let read = self.acc.cache_read.unwrap_or(0);
                let creation = self.acc.cache_creation.unwrap_or(0);
                if self.acc.input.is_none() && read == 0 && creation == 0 {
                    None
                } else {
                    Some(
                        self.acc
                            .input
                            .unwrap_or(0)
                            .saturating_add(read)
                            .saturating_add(creation),
                    )
                }
            }
            Shape::OpenAi => self.acc.input,
        };
        UsageObservation {
            model: self.acc.model.clone(),
            input_tokens,
            output_tokens: self.acc.output,
            total_tokens: self.acc.total.or(match (input_tokens, self.acc.output) {
                (Some(i), Some(o)) => Some(i.saturating_add(o)),
                _ => None,
            }),
            cached_input_tokens: self.acc.cache_read,
            state,
            was_streamed: self.streaming,
            dropped_events: self.dropped_events,
            model_rejected: self.acc.model_rejected,
        }
    }
}

impl BodyTap for UsageExtractor {
    fn feed(&mut self, bytes: &[u8]) {
        if self.unsupported || self.finished {
            return;
        }
        if !self.streaming {
            // Rolling tail window: append, then keep only the last
            // JSON_TAIL_WINDOW bytes. Memory is bounded by construction.
            self.tail.extend_from_slice(bytes);
            if self.tail.len() > JSON_TAIL_WINDOW {
                let drop = self.tail.len() - JSON_TAIL_WINDOW;
                self.tail.drain(..drop);
            }
            return;
        }
        for &b in bytes {
            if b == b'\n' {
                let line = std::mem::take(&mut self.line);
                self.on_line(&line);
            } else if self.line.len() >= MAX_LINE {
                // A pathological single line poisons the current event; keep
                // scanning for the next boundary WITHOUT retaining data.
                self.oversized = true;
                self.line.clear();
                self.line.shrink_to_fit();
            } else {
                self.line.push(b);
            }
        }
    }

    fn finish(&mut self) -> Option<UsageObservation> {
        Some(self.observation())
    }
}

/// Find the last `"usage": { ... }` object in a byte window by brace
/// matching. String-aware so a brace inside a string literal cannot confuse
/// it. Returns the object bytes only.
fn last_usage_object(window: &[u8]) -> Option<Vec<u8>> {
    let needle = b"\"usage\"";
    let mut start = None;
    let mut i = 0usize;
    while i + needle.len() <= window.len() {
        if &window[i..i + needle.len()] == needle {
            start = Some(i + needle.len());
        }
        i += 1;
    }
    let mut i = start?;
    while i < window.len() && (window[i] == b':' || window[i].is_ascii_whitespace()) {
        i += 1;
    }
    if i >= window.len() || window[i] != b'{' {
        return None;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, &b) in window[i..].iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(window[i..i + offset + 1].to_vec());
                }
            }
            _ => {}
        }
    }
    None
}

/// Decide the extraction mode for a response, from its declared headers.
///
/// A compressed response defeats a byte scan, and the relay NEVER
/// decompresses (zip-bomb surface), so it is honestly counted
/// `unsupported_shape` rather than silently reported as zero usage.
pub fn mode_for_response(
    content_type: Option<&str>,
    content_encoding: Option<&str>,
) -> (bool, bool) {
    let compressed = content_encoding
        .map(|e| {
            let e = e.trim().to_ascii_lowercase();
            !(e.is_empty() || e == "identity")
        })
        .unwrap_or(false);
    let streaming = content_type
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("text/event-stream")
        })
        .unwrap_or(false);
    (streaming, compressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(ex: &mut UsageExtractor, chunks: &[&[u8]]) -> UsageObservation {
        for c in chunks {
            ex.feed(c);
        }
        ex.observation()
    }

    #[test]
    fn openai_streaming_usage_is_extracted_from_the_terminal_chunk() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        let out = feed_all(
            &mut ex,
            &[
                b"data: {\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n",
                b"data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
                b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":34,\"total_tokens\":46,\"prompt_tokens_details\":{\"cached_tokens\":8}}}\n\n",
                b"data: [DONE]\n\n",
            ],
        );
        assert_eq!(out.model.as_deref(), Some("gpt-4o-mini"));
        assert_eq!(out.input_tokens, Some(12));
        assert_eq!(out.output_tokens, Some(34));
        assert_eq!(out.total_tokens, Some(46));
        assert_eq!(out.cached_input_tokens, Some(8));
        assert_eq!(out.state, UsageState::Extracted);
        assert!(out.was_streamed);
        assert!(out.available());
    }

    #[test]
    fn openai_streaming_without_include_usage_is_absent_never_zero() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        let out = feed_all(
            &mut ex,
            &[
                b"data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
                b"data: [DONE]\n\n",
            ],
        );
        assert_eq!(out.state, UsageState::Absent);
        assert_eq!(
            out.input_tokens, None,
            "absent usage is NEVER a fabricated 0"
        );
        assert_eq!(out.output_tokens, None);
        assert!(!out.available());
        assert_eq!(out.model.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn anthropic_sse_accumulates_message_start_and_message_delta() {
        // The REAL shape: input + cache counts in message_start (nested under
        // `message`), output in message_delta, with nulls in between that
        // must not clear anything.
        let mut ex = UsageExtractor::new(Shape::Anthropic, true, false);
        let out = feed_all(
            &mut ex,
            &[
                b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":25,\"cache_read_input_tokens\":100,\"cache_creation_input_tokens\":10,\"output_tokens\":1}}}\n\n",
                b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n",
                b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":73}}\n\n",
                b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ],
        );
        assert_eq!(out.model.as_deref(), Some("claude-sonnet-4-5"));
        // 25 base + 100 cache read + 10 cache creation.
        assert_eq!(out.input_tokens, Some(135));
        assert_eq!(out.output_tokens, Some(73), "message_delta output wins");
        assert_eq!(out.cached_input_tokens, Some(100));
        assert_eq!(out.state, UsageState::Extracted);
    }

    #[test]
    fn a_later_null_never_clears_a_populated_field() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        let out = feed_all(
            &mut ex,
            &[
                b"data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":20}}\n\n",
                b"data: {\"usage\":null}\n\n",
                b"data: {\"choices\":[]}\n\n",
            ],
        );
        assert_eq!(out.input_tokens, Some(10));
        assert_eq!(out.output_tokens, Some(20));
    }

    #[test]
    fn split_event_boundaries_across_feeds_still_parse() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        // One event delivered a byte at a time across many feed() calls.
        let event =
            b"data: {\"model\":\"gpt-4o\",\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":8}}\n\n";
        for b in event.iter() {
            ex.feed(&[*b]);
        }
        let out = ex.observation();
        assert_eq!(out.input_tokens, Some(7));
        assert_eq!(out.output_tokens, Some(8));

        // And split exactly at the CRLF/blank-line boundary.
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        ex.feed(b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}\r");
        ex.feed(b"\n");
        ex.feed(b"\r\n");
        let out = ex.observation();
        assert_eq!(out.input_tokens, Some(1));
    }

    #[test]
    fn a_pathological_event_is_dropped_wholesale_and_counted() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        ex.feed(b"data: ");
        let piece = vec![b'x'; 64 * 1024];
        for _ in 0..160 {
            ex.feed(&piece); // 10 MiB in one line
        }
        ex.feed(b"\n\n");
        assert_eq!(ex.dropped_events(), 1);
        assert!(ex.bound() <= MAX_LINE + MAX_EVENT);
        // A later well-formed event still parses.
        ex.feed(b"data: {\"model\":\"gpt-4o\",\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":9}}\n\n");
        let out = ex.observation();
        assert_eq!(out.input_tokens, Some(3));
        assert_eq!(out.output_tokens, Some(9));
        assert_eq!(out.dropped_events, 1);
        assert_eq!(out.state, UsageState::Extracted);
    }

    #[test]
    fn only_oversized_events_yield_the_oversized_state() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        ex.feed(b"data: ");
        ex.feed(&vec![b'x'; MAX_EVENT + 10]);
        ex.feed(b"\n\n");
        let out = ex.observation();
        assert_eq!(out.state, UsageState::OversizedDropped);
        assert_eq!(out.dropped_events, 1);
        assert_eq!(out.input_tokens, None);
    }

    #[test]
    fn non_streamed_json_uses_a_bounded_tail_window() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, false, false);
        let body = br#"{"id":"chatcmpl-1","model":"gpt-4o","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":11,"completion_tokens":22,"total_tokens":33}}"#;
        let out = feed_all(&mut ex, &[body]);
        assert_eq!(out.model.as_deref(), Some("gpt-4o"));
        assert_eq!(out.input_tokens, Some(11));
        assert_eq!(out.output_tokens, Some(22));
        assert_eq!(out.total_tokens, Some(33));
        assert!(!out.was_streamed);
    }

    #[test]
    fn a_huge_json_body_still_yields_the_trailing_usage_object() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, false, false);
        // A body far larger than the tail window: the head is discarded, and
        // the trailing usage object is still found by brace matching.
        ex.feed(b"{\"choices\":[{\"message\":{\"content\":\"");
        let filler = vec![b'a'; 32 * 1024];
        for _ in 0..8 {
            ex.feed(&filler); // 256 KiB
        }
        ex.feed(b"\"}}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":6}}");
        let out = ex.observation();
        assert_eq!(out.input_tokens, Some(5));
        assert_eq!(out.output_tokens, Some(6));
        assert!(ex.bound() <= JSON_TAIL_WINDOW);
    }

    #[test]
    fn a_brace_inside_a_string_cannot_confuse_the_window_scan() {
        let obj = last_usage_object(br#"{"usage":{"prompt_tokens":1,"note":"}{"},"x":2}"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&obj).unwrap();
        assert_eq!(v.get("prompt_tokens").unwrap().as_u64(), Some(1));
    }

    #[test]
    fn malformed_usage_is_labeled_not_guessed() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        let out = feed_all(&mut ex, &[b"data: {not json at all\n\n"]);
        assert_eq!(out.state, UsageState::Malformed);
        assert_eq!(out.input_tokens, None);

        let mut ex = UsageExtractor::new(Shape::OpenAi, false, false);
        let out = feed_all(&mut ex, &[b"<html>not json</html>"]);
        assert_eq!(out.state, UsageState::Malformed);
    }

    #[test]
    fn a_compressed_response_is_unsupported_never_silently_zero() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, false, true);
        let out = feed_all(&mut ex, &[b"\x1f\x8b\x08\x00garbage"]);
        assert_eq!(out.state, UsageState::UnsupportedShape);
        assert_eq!(out.input_tokens, None);
        assert!(!out.available());
    }

    #[test]
    fn response_mode_is_read_from_declared_headers() {
        assert_eq!(
            mode_for_response(Some("text/event-stream"), None),
            (true, false)
        );
        assert_eq!(
            mode_for_response(Some("text/event-stream; charset=utf-8"), Some("identity")),
            (true, false)
        );
        assert_eq!(
            mode_for_response(Some("application/json"), None),
            (false, false)
        );
        assert_eq!(
            mode_for_response(Some("application/json"), Some("gzip")),
            (false, true)
        );
        assert_eq!(mode_for_response(None, Some("br")), (false, true));
    }

    #[test]
    fn hostile_model_strings_are_rejected_not_truncated() {
        assert_eq!(
            sanitize_model("gpt-4o-mini").as_deref(),
            Some("gpt-4o-mini")
        );
        assert_eq!(
            sanitize_model("ft:gpt-4o-2024-08-06:acme:custom:abc123").as_deref(),
            Some("ft:gpt-4o-2024-08-06:acme:custom:abc123")
        );
        for hostile in [
            "",
            &"a".repeat(MAX_MODEL_LEN + 1),
            "gpt-4o'; DROP TABLE credentials;--",
            "gpt-4o\n\rX-Injected: 1",
            "model with spaces",
            "<script>alert(1)</script>",
            "sk-proj-FAKE00000000000000000000 leaked",
        ] {
            assert!(
                sanitize_model(hostile).is_none(),
                "{hostile:?} must be rejected outright, never truncated"
            );
        }

        // A hostile model in a real payload stores NULL and flags rejection.
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        let out = feed_all(
            &mut ex,
            &[b"data: {\"model\":\"gpt-4o \\\"injected\\\" value\",\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n"],
        );
        assert_eq!(out.model, None);
        assert!(out.model_rejected);
        assert_eq!(out.input_tokens, Some(1), "the numbers still extract");
    }

    #[test]
    fn an_unknown_shape_parses_nothing() {
        assert_eq!(Shape::parse("openai"), Some(Shape::OpenAi));
        assert_eq!(Shape::parse("anthropic"), Some(Shape::Anthropic));
        assert_eq!(Shape::parse(""), None);
        assert_eq!(Shape::parse("cohere"), None);
    }

    #[test]
    fn the_extractor_never_retains_prompt_or_completion_text() {
        // Route a body with known markers through the extractor and assert
        // that nothing it produces contains them.
        let prompt = "CANARY-PROMPT-MARKER-8f3a";
        let completion = "CANARY-COMPLETION-MARKER-2b71";
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        let out = feed_all(
            &mut ex,
            &[
                format!("data: {{\"model\":\"gpt-4o\",\"prompt\":\"{prompt}\",\"choices\":[{{\"delta\":{{\"content\":\"{completion}\"}}}}]}}\n\n").as_bytes(),
                b"data: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":5}}\n\n",
            ],
        );
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(!serialized.contains(prompt), "no prompt text may survive");
        assert!(
            !serialized.contains(completion),
            "no generated text may survive"
        );
        assert!(!serialized.contains("CANARY"));
        assert_eq!(out.input_tokens, Some(4));
    }
}

#[cfg(test)]
mod cache_accumulation_tests {
    use super::*;
    use crate::forward::BodyTap;

    /// Anthropic's `message_delta` carries the CUMULATIVE input and cache
    /// counts, not just the output. Adding them per frame double-counted
    /// every prompt-cached request; the counts must be idempotent.
    #[test]
    fn repeated_cumulative_cache_fields_are_not_double_counted() {
        let mut ex = UsageExtractor::new(Shape::Anthropic, true, false);
        ex.feed(b"data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":25,\"cache_read_input_tokens\":100,\"cache_creation_input_tokens\":10,\"output_tokens\":1}}}\n\n");
        // The delta REPEATS the cumulative input and cache fields.
        ex.feed(b"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":25,\"cache_read_input_tokens\":100,\"cache_creation_input_tokens\":10,\"output_tokens\":73}}\n\n");
        let out = ex.observation();
        assert_eq!(
            out.input_tokens,
            Some(135),
            "25 base + 100 cache read + 10 cache creation, counted ONCE"
        );
        assert_eq!(out.output_tokens, Some(73));
        assert_eq!(out.cached_input_tokens, Some(100));
        assert_eq!(out.total_tokens, Some(208));
    }

    #[test]
    fn a_third_repetition_still_does_not_inflate() {
        let mut ex = UsageExtractor::new(Shape::Anthropic, true, false);
        for _ in 0..3 {
            ex.feed(b"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":50,\"output_tokens\":5}}\n\n");
        }
        let out = ex.observation();
        assert_eq!(out.input_tokens, Some(60));
        assert_eq!(out.output_tokens, Some(5));
    }

    /// OpenAI reports cached tokens as a SUBSET of prompt_tokens, so they
    /// must NOT be added on top.
    #[test]
    fn openai_cached_tokens_are_a_subset_and_are_not_added() {
        let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
        ex.feed(b"data: {\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20,\"prompt_tokens_details\":{\"cached_tokens\":80}}}\n\n");
        let out = ex.observation();
        assert_eq!(
            out.input_tokens,
            Some(100),
            "OpenAI's cached_tokens are already inside prompt_tokens"
        );
        assert_eq!(out.cached_input_tokens, Some(80));
    }
}
