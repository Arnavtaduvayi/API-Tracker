//! Minimal HTTP client abstraction for provider connectors.
//!
//! Provider network calls go through the [`HttpClient`] trait so the request
//! construction and response parsing in [`crate::connectors`] are fully
//! testable offline with a [`MockHttpClient`] and scripted fixture responses.
//! The real implementation ([`UreqClient`]) makes the request directly from
//! the user's device with a short timeout. No credential value is ever logged
//! here; request headers that carry secrets are passed through opaquely.

use crate::error::{CoreError, Result};
use std::cell::RefCell;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// Requests carry bearer tokens and (for destinations) plaintext secret
/// bodies; Debug redacts both so a stray `{:?}` can never leak them.
impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| {
                let lower = k.to_ascii_lowercase();
                if lower == "authorization"
                    || lower == "x-amz-security-token"
                    || lower.contains("api-key")
                    || lower.contains("token")
                {
                    (k.as_str(), "[redacted]")
                } else {
                    (k.as_str(), v.as_str())
                }
            })
            .collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field(
                "body",
                &self.body.as_ref().map(|b| format!("[{} bytes]", b.len())),
            )
            .finish()
    }
}

impl HttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn with_method(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn body(mut self, bytes: Vec<u8>) -> Self {
        self.body = Some(bytes);
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Abstracts the HTTP transport. Implementors must not log secret headers.
pub trait HttpClient {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse>;
}

/// The real client, backed by a blocking `ureq` agent with a short timeout.
pub struct UreqClient {
    agent: ureq::Agent,
}

impl Default for UreqClient {
    fn default() -> Self {
        Self::new()
    }
}

impl UreqClient {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .user_agent("api-tracker/0.1 (+local)")
            // Non-2xx responses are VALUES here, with their bodies intact:
            // adapters parse error bodies (e.g. AWS `__type`) to decide
            // create-on-missing and to report honest errors.
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl HttpClient for UreqClient {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse> {
        // ureq 3.x uses typestate request builders, so each method is built
        // in its own branch rather than through a shared closure.
        let result = match req.method {
            Method::Get => {
                let mut r = self.agent.get(&req.url);
                for (k, v) in &req.headers {
                    r = r.header(k, v);
                }
                r.call()
            }
            Method::Post => {
                let mut r = self.agent.post(&req.url);
                for (k, v) in &req.headers {
                    r = r.header(k, v);
                }
                match &req.body {
                    Some(bytes) => r.send(&bytes[..]),
                    None => r.send_empty(),
                }
            }
            Method::Put => {
                let mut r = self.agent.put(&req.url);
                for (k, v) in &req.headers {
                    r = r.header(k, v);
                }
                match &req.body {
                    Some(bytes) => r.send(&bytes[..]),
                    None => r.send_empty(),
                }
            }
            Method::Delete => {
                let mut r = self.agent.delete(&req.url);
                for (k, v) in &req.headers {
                    r = r.header(k, v);
                }
                r.call()
            }
        };
        let mut resp = match result {
            Ok(resp) => resp,
            // Unreachable with http_status_as_error(false); kept as a net.
            Err(ureq::Error::StatusCode(code)) => {
                return Ok(HttpResponse {
                    status: code,
                    headers: Vec::new(),
                    body: Vec::new(),
                });
            }
            Err(e) => {
                // Transport-level failure (DNS, refused, timeout, TLS). The
                // ureq error Display never includes request headers, so no
                // secret can leak here.
                return Err(CoreError::Network(format!("request failed: {e}")));
            }
        };
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp
            .body_mut()
            .with_config()
            .limit(4 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| CoreError::InvalidInput(format!("could not read response body: {e}")))?;
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// A scripted client for tests: pops a queued response per call and records
/// the requests it received for assertions.
#[derive(Default)]
pub struct MockHttpClient {
    responses: RefCell<Vec<HttpResponse>>,
    /// Number of initial sends that fail with a transport error before the
    /// queued responses are served (simulates an offline network).
    network_failures: RefCell<u32>,
    pub requests: RefCell<Vec<HttpRequest>>,
}

impl MockHttpClient {
    pub fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: RefCell::new(responses),
            network_failures: RefCell::new(0),
            requests: RefCell::new(Vec::new()),
        }
    }

    /// Fail the first `failures` sends with [`CoreError::Network`], then
    /// serve the queued responses.
    pub fn with_network_failures(failures: u32, responses: Vec<HttpResponse>) -> Self {
        let mock = Self::new(responses);
        *mock.network_failures.borrow_mut() = failures;
        mock
    }

    /// A 200 JSON response value, for building multi-response queues.
    pub fn json_response(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
        }
    }

    /// A single JSON 200 response.
    pub fn json(body: &str) -> Self {
        Self::new(vec![HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
        }])
    }

    /// A single response with a status and headers (e.g. GitHub scope header).
    pub fn with(status: u16, headers: Vec<(String, String)>, body: &str) -> Self {
        Self::new(vec![HttpResponse {
            status,
            headers,
            body: body.as_bytes().to_vec(),
        }])
    }

    pub fn last_request(&self) -> Option<HttpRequest> {
        self.requests.borrow().last().cloned()
    }
}

impl HttpClient for MockHttpClient {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse> {
        self.requests.borrow_mut().push(req.clone());
        {
            let mut failures = self.network_failures.borrow_mut();
            if *failures > 0 {
                *failures -= 1;
                return Err(CoreError::Network("mock: simulated offline".into()));
            }
        }
        let mut responses = self.responses.borrow_mut();
        if responses.is_empty() {
            return Err(CoreError::InvalidInput(
                "mock: no more responses queued".into(),
            ));
        }
        Ok(responses.remove(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_pops_responses_and_records_requests() {
        let mock = MockHttpClient::json(r#"{"ok":true}"#);
        let req = HttpRequest::get("https://example.com/x").header("Authorization", "Bearer z");
        let resp = mock.send(&req).unwrap();
        assert!(resp.is_success());
        assert_eq!(resp.body_str(), r#"{"ok":true}"#);
        assert_eq!(mock.last_request().unwrap().url, "https://example.com/x");
        // Exhausted queue errors rather than hanging.
        assert!(mock.send(&req).is_err());
    }

    #[test]
    fn response_header_lookup_is_case_insensitive() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![("X-OAuth-Scopes".into(), "repo, read:org".into())],
            body: Vec::new(),
        };
        assert_eq!(resp.header("x-oauth-scopes"), Some("repo, read:org"));
        assert_eq!(resp.header("missing"), None);
    }
}
