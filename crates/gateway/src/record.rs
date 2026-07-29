//! What one forwarded exchange may hand to the observation writer.
//!
//! This is the gateway's structural privacy boundary, the counterpart of
//! `core::runtime::model::ObservedRequest`: **there is no field able to hold a
//! body, a header value, a cookie, an authorization value, a query string, or
//! a raw URL.** Anything not representable here cannot be persisted, logged,
//! or queued, whatever a future code path attempts (PRIVACY_MODEL §2).

use api_tracker_core::runtime::model::{ContentKind, HttpMethod, TransportError};

/// How the exchange ended. `Completed` is claimed only when the full body was
/// relayed with its declared framing; every other case is recorded honestly
/// rather than being flattened into "success".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    Completed,
    /// The client went away mid-request or mid-response.
    ClientDisconnected,
    /// The upstream closed before sending any response byte.
    UpstreamDisconnected,
    /// A declared Content-Length was not fully delivered, or a chunked body
    /// ended mid-chunk. Connection-terminal, never retried.
    Truncated,
    /// The gateway refused the request locally (framing, host, method).
    RejectedLocally,
    /// A transport or TLS failure reaching the upstream.
    UpstreamFailed,
    /// The request body was still arriving when its own absolute upload
    /// deadline (`CLIENT_BODY_DEADLINE`) ran out.
    ///
    /// `NEW-52`: this used to be recorded as `ClientDisconnected` + `Reset` —
    /// byte-identical to the peer vanishing — so an operator could not tell
    /// "our limit cut this client off" from "this client died". The three
    /// variants below are all OUR decision; `ClientDisconnected` now means
    /// only the peer's.
    ClientBodyDeadlineExceeded,
    /// The request body was cut short because the CONNECTION's cumulative
    /// client-paced budget (`CLIENT_CONNECTION_TIME_BUDGET`) ran out, not this
    /// request's own deadline. Distinct because the remedy differs: the client
    /// should open a fresh connection, not send a smaller body.
    ConnectionBudgetExceeded,
    /// No byte of the request body arrived for `CLIENT_BODY_IDLE_TIMEOUT`.
    /// The client is still connected; it simply stopped sending.
    ClientBodyIdleTimeout,
}

impl Completion {
    pub fn as_str(self) -> &'static str {
        match self {
            Completion::Completed => "completed",
            Completion::ClientDisconnected => "client_disconnected",
            Completion::UpstreamDisconnected => "upstream_disconnected",
            Completion::Truncated => "truncated",
            Completion::RejectedLocally => "rejected_locally",
            Completion::UpstreamFailed => "upstream_failed",
            Completion::ClientBodyDeadlineExceeded => "client_body_deadline_exceeded",
            Completion::ConnectionBudgetExceeded => "connection_budget_exceeded",
            Completion::ClientBodyIdleTimeout => "client_body_idle_timeout",
        }
    }

    /// Whether the gateway itself ended the exchange by enforcing one of its
    /// own client-facing limits, rather than the peer ending it.
    ///
    /// `NEW-52`: the wire answer differs too — these get a 408, a client
    /// disconnect gets nothing, because there is nobody left to answer.
    pub fn is_gateway_imposed_limit(self) -> bool {
        matches!(
            self,
            Completion::ClientBodyDeadlineExceeded
                | Completion::ConnectionBudgetExceeded
                | Completion::ClientBodyIdleTimeout
        )
    }
    /// Whether the recorded metadata covers the whole exchange. A partial
    /// exchange is labeled partial rather than presented as complete.
    pub fn is_complete_coverage(self) -> bool {
        matches!(self, Completion::Completed)
    }
}

/// Why usage numbers are or are not present. A missing number is never a
/// silent zero (PRIVACY_MODEL gateway §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageState {
    /// No usage object appeared in a shape the gateway understands.
    #[default]
    Absent,
    Extracted,
    /// Compressed, or a provider/response shape with no declared extractor.
    UnsupportedShape,
    /// An event exceeded the per-event cap and was discarded wholesale.
    OversizedDropped,
    /// A usage object was found but could not be parsed.
    Malformed,
}

impl UsageState {
    pub fn as_str(self) -> &'static str {
        match self {
            UsageState::Absent => "absent",
            UsageState::Extracted => "extracted",
            UsageState::UnsupportedShape => "unsupported_shape",
            UsageState::OversizedDropped => "oversized_dropped",
            UsageState::Malformed => "malformed",
        }
    }
}

/// Bounded, allowlisted usage metadata. Numbers and one constrained model
/// string — nothing else is ever extracted from a body.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct UsageObservation {
    pub model: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub state: UsageState,
    pub was_streamed: bool,
    /// Oversized events discarded during extraction (coverage honesty).
    pub dropped_events: u64,
    /// A model string that failed the length/charset filter was rejected
    /// rather than truncated into the database.
    pub model_rejected: bool,
}

impl UsageObservation {
    pub fn available(&self) -> bool {
        self.state == UsageState::Extracted
            && (self.input_tokens.is_some() || self.output_tokens.is_some())
    }
}

/// The transient, keyed digest of a presented credential value.
///
/// This is a keyed BLAKE3 fingerprint (ADR 0005 construction) — NOT the
/// value, and never an unkeyed hash. It is computed on the forwarding path
/// and resolved against the scoped matcher table on the writer thread, so no
/// forwarding-path timing depends on whether a credential matched.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialDigest {
    /// Candidate fingerprints (scheme-stripped and whole-value forms).
    pub candidates: Vec<[u8; 32]>,
}

impl std::fmt::Debug for CredentialDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Even a keyed digest is not printed: it is a matching oracle input.
        f.debug_struct("CredentialDigest")
            .field("candidates", &self.candidates.len())
            .finish()
    }
}

/// Why attribution could not produce a digest, when it could not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionInput {
    /// A recognized credential header was present and digested.
    Digested,
    /// No recognized credential header on the request.
    NoCredentialPresent,
    /// A credential header was present but not in a supported form
    /// (`Basic`, or a query/cookie-borne credential — out of scope v1).
    UnsupportedForm,
    /// The matching key is not in memory (vault locked, or the toggle is
    /// off). Recorded as such — NEVER as "unmatched".
    UnavailableNoKey,
}

/// One forwarded exchange, as handed to the writer.
#[derive(Debug, Clone)]
pub struct ExchangeRecord {
    /// RFC 3339 timestamp captured when the request head was read — the
    /// event's own time, not persist time.
    pub at: String,
    pub route_prefix: String,
    pub provider_id: String,
    /// Resolved from the link slug; `None` for unlinked (bare-prefix)
    /// traffic, which is counted at route level and never given an invented
    /// project attribution.
    pub project_id: Option<String>,
    /// The UPSTREAM host — from the route table, never from a client-sent
    /// Host header.
    pub host: String,
    pub port: u16,
    pub method: HttpMethod,
    /// `sanitize_path` output over the route-stripped path, with query and
    /// fragment severed BEFORE sanitization.
    pub path_template: String,
    pub template_confidence: api_tracker_core::providers::Confidence,
    pub status_code: Option<u16>,
    pub req_content_kind: Option<ContentKind>,
    pub resp_content_kind: Option<ContentKind>,
    /// Presence only.
    pub had_authorization: bool,
    pub latency_ms: Option<i64>,
    /// Time to first response byte, for streaming honesty.
    pub ttfb_ms: Option<i64>,
    pub request_bytes: Option<i64>,
    pub response_bytes: Option<i64>,
    pub transport_error: TransportError,
    pub completion: Completion,
    pub attribution_input: AttributionInput,
    pub digest: Option<CredentialDigest>,
    pub usage: Option<UsageObservation>,
}

/// Counters the forwarding path may bump. Each is content-free.
pub mod counters {
    /// Requests forwarded with no project link (route-level only).
    pub const UNLINKED_REQUESTS: &str = "unlinked_requests";
    /// Requests refused as browser-originated (THREAT_MODEL GW-2). This is
    /// the ONLY record such a request produces.
    pub const REJECTED_BROWSER_ORIGIN: &str = "rejected_browser_origin";
    /// Requests refused by local validation (framing, host, method, path).
    pub const REJECTED_LOCALLY: &str = "rejected_locally";
    /// Requests for an unregistered prefix or slug.
    pub const UNKNOWN_ROUTE: &str = "unknown_route";
    /// Custom routes refused because their origin MAC could not be verified.
    pub const ROUTE_UNAVAILABLE: &str = "route_unavailable";
    /// Connections refused because the concurrency cap was reached.
    pub const CONNECTION_CAP_REACHED: &str = "connection_cap_reached";
    /// Observation events dropped because the writer queue was full.
    pub const DROPPED_EVENTS: &str = "dropped_events";
    /// Model strings rejected by the length/charset filter.
    pub const MODEL_REJECTED: &str = "model_rejected";
    /// Oversized streaming events discarded by the bounded extractor.
    pub const USAGE_EVENTS_DROPPED: &str = "usage_events_dropped";
    /// Connections still running when a clean stop hit its drain deadline.
    pub const SHUTDOWN_ABANDONED_CONNECTIONS: &str = "shutdown_abandoned_connections";
}

/// Where observations go. Implementations MUST NOT block the forwarding
/// path: a full queue drops and counts (SI-12).
pub trait ObservationSink: Send + Sync {
    /// Hand off one exchange. Never blocks; never fails the caller.
    fn record(&self, record: ExchangeRecord);
    /// Bump a content-free counter. `route_prefix` is `""` for
    /// gateway-global counters.
    fn count(&self, route_prefix: &str, counter: &str);
}

/// A sink that discards everything — used when recording is paused and by
/// forwarding-only tests. Forwarding must work identically with it.
pub struct NullSink;

impl ObservationSink for NullSink {
    fn record(&self, _record: ExchangeRecord) {}
    fn count(&self, _route_prefix: &str, _counter: &str) {}
}
