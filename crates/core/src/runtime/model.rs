//! Data model for runtime API observability: the enums stored as strings in
//! the `runtime_*` / `observation_*` / `observed_*` tables, the DTO structs
//! returned to the CLI and desktop, and the classification helpers that derive
//! status class / outcome / content kind from raw wire facts.
//!
//! [`ObservedRequest`] is the type-level privacy boundary: it has no field
//! capable of holding a body, a header value, a cookie, an authorization value,
//! a query string, or a raw URL. The proxy assembles it from sanitized parts
//! (see [`crate::runtime::sanitize`]) and hands it to
//! [`crate::runtime::store::insert_request_event`]; there is no other path from
//! the wire into the database.

use crate::providers::Confidence;
use serde::Serialize;

/// Generate a string-backed enum with `as_str`, `from_db`, `Serialize`
/// (as the snake_case string), and `Display`. Matches the codebase convention
/// of storing enum values as their snake_case string form.
macro_rules! str_enum {
    ($(#[$m:meta])* $name:ident { $($variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $s),+ } }
            pub fn from_db(s: &str) -> Option<Self> {
                match s { $($s => Some(Self::$variant),)+ _ => None }
            }
        }
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
                ser.serialize_str(self.as_str())
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

str_enum! {
    /// The observation mode selected for a run. Mode C (system trust) is a
    /// separate certificate decision, not a run mode.
    ObservationMode {
        Off => "off",
        Connection => "connection",
        Metadata => "metadata",
    }
}

impl ObservationMode {
    /// Parse a `--observe=<mode>` value, tolerating a couple of aliases.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "false" => Some(Self::Off),
            "connection" | "conn" | "tcp" => Some(Self::Connection),
            "metadata" | "meta" | "full" | "on" | "true" => Some(Self::Metadata),
            _ => None,
        }
    }
}

str_enum! {
    /// HTTP request methods we recognise; anything else is `Other` (its exact
    /// text is never stored — an unknown verb becomes the enum, not a string).
    HttpMethod {
        Get => "GET", Post => "POST", Put => "PUT", Delete => "DELETE",
        Patch => "PATCH", Head => "HEAD", Options => "OPTIONS",
        Trace => "TRACE", Connect => "CONNECT", Other => "OTHER",
    }
}

impl HttpMethod {
    pub fn parse(s: &str) -> Self {
        match s {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            _ => Self::Other,
        }
    }
}

str_enum! {
    /// The class of an HTTP status code, or `None` when no response arrived.
    StatusClass {
        Informational => "1xx", Success => "2xx", Redirect => "3xx",
        ClientError => "4xx", ServerError => "5xx", None => "none",
    }
}

impl StatusClass {
    pub fn of(code: u16) -> Self {
        match code {
            100..=199 => Self::Informational,
            200..=299 => Self::Success,
            300..=399 => Self::Redirect,
            400..=499 => Self::ClientError,
            500..=599 => Self::ServerError,
            _ => Self::None,
        }
    }
}

str_enum! {
    /// The distilled outcome of a request. Kept deliberately separate so a 4xx
    /// is never conflated with a provider outage and a transport failure is
    /// never counted as an HTTP error rate.
    Outcome {
        Success => "success",
        ClientError => "client_error",
        AuthError => "auth_error",
        RateLimited => "rate_limited",
        ServerError => "server_error",
        TransportError => "transport_error",
        TlsError => "tls_error",
    }
}

str_enum! {
    /// A transport/TLS failure category (no response, or an early failure).
    TransportError {
        None => "none",
        Dns => "dns",
        Refused => "refused",
        Reset => "reset",
        Timeout => "timeout",
        UpstreamCertInvalid => "upstream_cert_invalid",
        ProxyError => "proxy_error",
    }
}

impl TransportError {
    pub fn is_failure(self) -> bool {
        !matches!(self, TransportError::None)
    }
}

str_enum! {
    /// What we negotiated / observed on the connection.
    Protocol {
        PlainHttp => "plain_http",
        Http10 => "http1.0",
        Http11 => "http1.1",
        H2Opaque => "h2_opaque",
        Websocket => "websocket",
        ConnectTunnel => "connect_tunnel",
    }
}

str_enum! {
    /// How the event was observed.
    ObservationSource {
        Intercept => "intercept",
        ConnectionOnly => "connection_only",
        UpgradeThenOpaque => "upgrade_then_opaque",
    }
}

str_enum! {
    /// The lifecycle state of an observation session. `Interrupted` is a
    /// distinct, honestly-reported state — a session is never silently
    /// `Completed`.
    SessionStatus {
        Running => "running",
        Completed => "completed",
        Interrupted => "interrupted",
    }
}

str_enum! {
    /// How confident we are that traffic belongs to a particular credential.
    /// Derived only from what Tethra controls (injection, mappings, project,
    /// host→provider, launch-time version) — never from reading an
    /// authorization value.
    AttributionConfidence {
        Confirmed => "confirmed",
        High => "high",
        Possible => "possible",
        Ambiguous => "ambiguous",
        Unattributed => "unattributed",
    }
}

str_enum! {
    /// The source of an entry in the API inventory — labelled honestly so
    /// locally observed data is never presented as provider-reported.
    ServiceSource {
        LocallyObserved => "locally_observed",
        ProviderReported => "provider_reported",
        UserEntered => "user_entered",
        Inferred => "inferred",
        RepositoryDetected => "repository_detected",
        Unknown => "unknown",
    }
}

str_enum! {
    /// The runtime-trust assessment for a monitored session.
    TrustLevel {
        FullySupported => "fully_supported",
        ProbablySupported => "probably_supported",
        ConnectionOnlyFallback => "connection_only_fallback",
        Unsupported => "unsupported",
        PinningSuspected => "pinning_suspected",
        ProxyBypassSuspected => "proxy_bypass_suspected",
    }
}

str_enum! {
    /// Whether an observed service is classified external or internal.
    ServiceClass {
        External => "external",
        Internal => "internal",
    }
}

str_enum! {
    /// A coarse, parameter-stripped content-type category. The raw
    /// Content-Type (which can carry a multipart boundary or charset) is never
    /// stored — only this closed set.
    ContentKind {
        Json => "json",
        Form => "form",
        Multipart => "multipart",
        Xml => "xml",
        Text => "text",
        Html => "html",
        Grpc => "grpc",
        EventStream => "event_stream",
        OctetStream => "octet_stream",
        Graphql => "graphql",
        Other => "other",
    }
}

impl ContentKind {
    /// Classify a raw `Content-Type` header value. Everything after the first
    /// `;` (charset, multipart boundary, …) is severed before mapping, so no
    /// parameter is ever inspected or stored.
    pub fn classify(raw: &str) -> Self {
        let base = raw.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        match base.as_str() {
            "application/json" => Self::Json,
            "application/graphql" => Self::Graphql,
            "application/x-www-form-urlencoded" => Self::Form,
            "multipart/form-data" | "multipart/mixed" => Self::Multipart,
            "application/xml" | "text/xml" => Self::Xml,
            "text/html" => Self::Html,
            "text/event-stream" => Self::EventStream,
            "application/octet-stream" => Self::OctetStream,
            "application/grpc" | "application/grpc+proto" | "application/grpc+json" => Self::Grpc,
            other => {
                if other.starts_with("text/") {
                    Self::Text
                } else if other.ends_with("+json") {
                    Self::Json
                } else if other.ends_with("+xml") {
                    Self::Xml
                } else {
                    Self::Other
                }
            }
        }
    }
}

/// Derive the outcome from the status code and transport-error category.
///
/// Precedence: an upstream certificate failure is a TLS error; any other
/// transport failure (including "no response") is a transport error; only when
/// a real HTTP response arrived is the status consulted. A successful TCP
/// connection with no HTTP response is therefore NEVER a success.
pub fn outcome_of(status: Option<u16>, transport: TransportError) -> Outcome {
    match transport {
        TransportError::UpstreamCertInvalid => return Outcome::TlsError,
        TransportError::None => {}
        _ => return Outcome::TransportError,
    }
    match status {
        None => Outcome::TransportError,
        Some(401) => Outcome::AuthError,
        Some(429) => Outcome::RateLimited,
        Some(c) if (200..=399).contains(&c) => Outcome::Success,
        Some(c) if (400..=499).contains(&c) => Outcome::ClientError,
        Some(c) if (500..=599).contains(&c) => Outcome::ServerError,
        Some(_) => Outcome::TransportError,
    }
}

/// The sanitized, metadata-only description of one observed request. **This
/// type is the privacy boundary**: it has no field able to hold a body, a
/// header value, a cookie, an authorization value, a query string, or a raw
/// URL. Adding such a field is the only way to break the metadata-only
/// guarantee, and it is a five-line review to confirm none exists.
#[derive(Debug, Clone)]
pub struct ObservedRequest {
    pub host: String,
    pub port: u16,
    pub method: HttpMethod,
    pub path_template: String,
    pub template_confidence: Confidence,
    pub status_code: Option<u16>,
    pub req_content_kind: Option<ContentKind>,
    pub resp_content_kind: Option<ContentKind>,
    pub had_authorization: bool,
    pub latency_ms: Option<i64>,
    pub request_bytes: Option<i64>,
    pub response_bytes: Option<i64>,
    pub protocol: Protocol,
    pub observation_source: ObservationSource,
    pub transport_error: TransportError,
}

impl ObservedRequest {
    pub fn status_class(&self) -> StatusClass {
        self.status_code.map(StatusClass::of).unwrap_or(StatusClass::None)
    }
    pub fn outcome(&self) -> Outcome {
        outcome_of(self.status_code, self.transport_error)
    }
}

// --- Row DTOs returned to the CLI / desktop (all metadata-only, Serialize) ---

#[derive(Debug, Clone, Serialize)]
pub struct ObservationSessionRow {
    pub id: String,
    pub project_id: String,
    pub mode: String,
    pub source: String,
    pub status: String,
    pub interrupt_reason: Option<String>,
    pub command: String,
    pub credential_names: String,
    pub runtime_detected: Option<String>,
    pub trust_level: Option<String>,
    pub partial_coverage: bool,
    pub proxy_port: Option<i64>,
    pub pid: Option<i64>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub exit_code: Option<i64>,
    pub request_count: i64,
    pub error_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservedServiceRow {
    pub id: String,
    pub host: String,
    pub provider_id: Option<String>,
    pub source: String,
    pub classification: String,
    pub is_internal: bool,
    pub user_provider: Option<String>,
    pub user_api_name: Option<String>,
    pub user_notes: Option<String>,
    pub confirmed: bool,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservedEndpointRow {
    pub id: String,
    pub service_id: String,
    pub method: String,
    pub path_template: String,
    pub template_confidence: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

/// A recent event, for the "recent sanitized events" table. Carries only
/// metadata; there is deliberately no body/header/query field.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeEventRow {
    pub at: String,
    pub host: String,
    pub method: String,
    pub path_template: String,
    pub status_code: Option<i64>,
    pub outcome: String,
    pub latency_ms: Option<i64>,
    pub request_bytes: Option<i64>,
    pub response_bytes: Option<i64>,
    pub protocol: String,
    pub observation_source: String,
    pub attribution_confidence: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialAttributionRow {
    pub session_id: String,
    pub credential_id: String,
    pub service_id: String,
    pub host: String,
    pub request_count: i64,
    pub confidence: String,
    pub evidence: String,
    pub credential_version: Option<i64>,
    pub used_current_version: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompatibilityResultRow {
    pub session_id: String,
    pub check: String,
    pub status: String,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_never_confuses_transport_with_http() {
        // A transport failure is never an HTTP error rate.
        assert_eq!(
            outcome_of(None, TransportError::Refused),
            Outcome::TransportError
        );
        // A TCP success with no HTTP response is NOT a request success.
        assert_eq!(outcome_of(None, TransportError::None), Outcome::TransportError);
        // Upstream cert failure is a TLS error, distinct from HTTP.
        assert_eq!(
            outcome_of(Some(200), TransportError::UpstreamCertInvalid),
            Outcome::TlsError
        );
        assert_eq!(outcome_of(Some(200), TransportError::None), Outcome::Success);
        assert_eq!(outcome_of(Some(301), TransportError::None), Outcome::Success);
        assert_eq!(outcome_of(Some(401), TransportError::None), Outcome::AuthError);
        assert_eq!(outcome_of(Some(403), TransportError::None), Outcome::ClientError);
        assert_eq!(outcome_of(Some(429), TransportError::None), Outcome::RateLimited);
        assert_eq!(outcome_of(Some(404), TransportError::None), Outcome::ClientError);
        assert_eq!(outcome_of(Some(500), TransportError::None), Outcome::ServerError);
    }

    #[test]
    fn content_kind_strips_parameters() {
        assert_eq!(
            ContentKind::classify("multipart/form-data; boundary=----abcXYZ123"),
            ContentKind::Multipart
        );
        assert_eq!(ContentKind::classify("application/json; charset=utf-8"), ContentKind::Json);
        assert_eq!(ContentKind::classify("text/event-stream"), ContentKind::EventStream);
        assert_eq!(ContentKind::classify("application/grpc+proto"), ContentKind::Grpc);
        assert_eq!(ContentKind::classify("application/vnd.api+json"), ContentKind::Json);
        assert_eq!(ContentKind::classify("text/csv"), ContentKind::Text);
    }

    #[test]
    fn enums_roundtrip_through_db_strings() {
        for m in [ObservationMode::Off, ObservationMode::Connection, ObservationMode::Metadata] {
            assert_eq!(ObservationMode::from_db(m.as_str()), Some(m));
        }
        assert_eq!(SessionStatus::from_db("interrupted"), Some(SessionStatus::Interrupted));
        assert_eq!(Outcome::from_db("auth_error"), Some(Outcome::AuthError));
        assert_eq!(HttpMethod::parse("PATCH"), HttpMethod::Patch);
        assert_eq!(HttpMethod::parse("WEIRD"), HttpMethod::Other);
    }

    #[test]
    fn mode_parse_accepts_aliases() {
        assert_eq!(ObservationMode::parse("META"), Some(ObservationMode::Metadata));
        assert_eq!(ObservationMode::parse("conn"), Some(ObservationMode::Connection));
        assert_eq!(ObservationMode::parse("off"), Some(ObservationMode::Off));
        assert_eq!(ObservationMode::parse("bogus"), None);
    }
}
