//! Path-template sanitization — the persistence boundary for observed URLs.
//!
//! This module is pure and deterministic. It is the ONLY thing permitted to
//! turn a wire-derived request target into a stored string, and callers run it
//! *before* the value ever reaches [`crate::runtime::store`]. Query strings and
//! fragments are severed before templating begins; identifier-shaped path
//! segments (UUIDs, long integers, emails, tokens, hashes, high-entropy blobs)
//! are replaced with `:placeholder`s; only stable, low-entropy structure is
//! kept.
//!
//! The guarantees are pinned by the property tests at the bottom of this file
//! (see `docs/observability/RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md` §5). In
//! particular the OUTPUT never contains: a run of ≥5 digits (P2), a run of ≥16
//! hex chars (P3), a UUID (P4), an `@` (P5), or a high-entropy segment (P6).

use crate::providers::Confidence;

/// Maximum bytes of path we template; longer paths are truncated.
const MAX_LEN: usize = 512;
/// Maximum number of `/`-separated parts we template.
const MAX_PARTS: usize = 20;

/// Sanitize a raw request target into `(path_template, confidence)`.
///
/// `confidence` is the *minimum* per-segment confidence: `High` when every
/// segment is a confident classification or a kept low-entropy literal,
/// `Medium` when a heuristic (high-entropy / filename) fired, `Low` when a
/// conservative `:redacted` fallback or truncation was needed.
pub fn sanitize_path(raw: &str) -> (String, Confidence) {
    // 1. Sever query and fragment IMMEDIATELY. Everything after the first
    //    '?' or '#' is dropped here and never assigned to a lasting binding.
    let cut = raw
        .find(['?', '#'])
        .map(|i| &raw[..i])
        .unwrap_or(raw);

    // 2. A target we do not understand (empty, not origin-form) is redacted
    //    wholesale rather than guessed at. `*` (OPTIONS asterisk-form) is a
    //    known safe literal.
    if cut == "*" {
        return ("*".to_string(), Confidence::High);
    }
    if cut.is_empty() || !cut.starts_with('/') {
        return ("/:redacted".to_string(), Confidence::Low);
    }

    let mut confidence = Confidence::High;
    let mut out = String::with_capacity(cut.len().min(MAX_LEN) + 8);
    let mut parts = 0usize;
    let mut truncated = false;

    // split('/') on "/a/b/" yields ["", "a", "b", ""]; the leading and any
    // internal/trailing empties are preserved so path structure survives.
    for (idx, seg) in cut.split('/').enumerate() {
        if idx > 0 {
            out.push('/');
        }
        if parts >= MAX_PARTS || out.len() >= MAX_LEN {
            out.push_str(":truncated");
            truncated = true;
            break;
        }
        if seg.is_empty() {
            // preserve the empty (leading slash / double slash / trailing)
            continue;
        }
        parts += 1;
        let (rendered, seg_conf) = classify_segment(seg);
        confidence = confidence.min(seg_conf);
        out.push_str(&rendered);
    }

    if truncated {
        confidence = Confidence::Low;
    }
    if out.is_empty() {
        out.push('/');
    }
    (out, confidence)
}

/// Classify one non-empty path segment. The FIRST matching rule wins; a rule
/// that fires on a sensitive class replaces the whole segment.
fn classify_segment(seg: &str) -> (String, Confidence) {
    if is_uuid(seg) {
        return (":uuid".into(), Confidence::High);
    }
    if is_jwt(seg) {
        return (":jwt".into(), Confidence::High);
    }
    if is_email(seg) {
        return (":email".into(), Confidence::High);
    }
    if is_credential_shaped(seg) {
        return (":token".into(), Confidence::High);
    }
    // Long integer (order ids, user ids, ...) BEFORE long-hex, so an all-digit
    // run is labelled :id rather than :hash.
    if is_all_digits(seg) && seg.len() >= 2 {
        return (":id".into(), Confidence::High);
    }
    if is_long_hex(seg) {
        return (":hash".into(), Confidence::High);
    }
    // A filename that embeds a sensitive run (invoice_<hex>.pdf) gets the
    // nicer `:file` label — checked BEFORE the generic high-entropy rule so a
    // hashed filename is not merely `:token`.
    if looks_like_filename(seg) && has_embedded_sensitive(seg) {
        return (":file".into(), Confidence::Medium);
    }
    if is_high_entropy(seg) {
        return (":token".into(), Confidence::Medium);
    }
    // Any remaining segment that still embeds a sensitive run must not be kept
    // verbatim, or P2/P3/P4/P5 would break.
    if has_embedded_sensitive(seg) {
        return (":redacted".into(), Confidence::Low);
    }
    if seg.len() > 40 || has_unprintable(seg) {
        return (":redacted".into(), Confidence::Low);
    }
    // Kept: a stable, low-entropy collection/resource name (users, v1, chat…).
    (seg.to_string(), Confidence::High)
}

fn is_hex_byte(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            _ => {
                if !is_hex_byte(c) {
                    return false;
                }
            }
        }
    }
    true
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_long_hex(s: &str) -> bool {
    s.len() >= 16 && s.bytes().all(is_hex_byte)
}

fn is_email(s: &str) -> bool {
    match s.split_once('@') {
        Some((local, domain)) => !local.is_empty() && domain.contains('.') && !domain.starts_with('.'),
        None => false,
    }
}

/// Known credential/token prefixes. A path segment starting with one of these
/// is almost certainly a leaked secret in the URL and is replaced with `:token`.
const CREDENTIAL_PREFIXES: &[&str] = &[
    "sk-", "sk_", "pk_live", "pk_test", "rk_live", "rk_test", "whsec_",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
    "AKIA", "ASIA", "AIza", "ya29.", "glpat-", "shpat_", "shpss_", "shpca_",
    "Bearer", "eyJ",
];

fn is_credential_shaped(s: &str) -> bool {
    // eyJ is handled by is_jwt; keep it here too for bare single-part tokens.
    CREDENTIAL_PREFIXES.iter().any(|p| s.starts_with(p)) && s.len() >= 8
}

fn is_base64url_charset(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
}

fn is_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts[0].starts_with("eyJ")
        && parts.iter().all(|p| p.len() >= 8 && is_base64url_charset(p))
}

/// Character-class diversity + length heuristic for opaque tokens.
fn is_high_entropy(s: &str) -> bool {
    if s.len() < 20 {
        return false;
    }
    let (mut lower, mut upper, mut digit, mut other) = (false, false, false, false);
    for b in s.bytes() {
        match b {
            b'a'..=b'z' => lower = true,
            b'A'..=b'Z' => upper = true,
            b'0'..=b'9' => digit = true,
            _ => other = true,
        }
    }
    let classes = [lower, upper, digit, other].iter().filter(|x| **x).count();
    // len ≥ 20 with ≥3 classes, OR a long base64url-ish blob with both letters
    // and digits.
    (classes >= 3)
        || (s.len() >= 24 && is_base64url_charset(s) && (lower || upper) && digit)
}

/// Longest run of consecutive ASCII digits.
fn max_digit_run(s: &str) -> usize {
    let mut best = 0;
    let mut cur = 0;
    for b in s.bytes() {
        if b.is_ascii_digit() {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

/// Longest run of consecutive ASCII hex digits.
fn max_hex_run(s: &str) -> usize {
    let mut best = 0;
    let mut cur = 0;
    for b in s.bytes() {
        if is_hex_byte(b) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

fn contains_uuid_substring(s: &str) -> bool {
    // cheap scan: any 36-char window that is a UUID.
    let b = s.as_bytes();
    if b.len() < 36 {
        return false;
    }
    (0..=b.len() - 36).any(|i| is_uuid(&s[i..i + 36]))
}

/// A segment that still embeds an identifier-shaped run and therefore must not
/// be kept verbatim.
fn has_embedded_sensitive(s: &str) -> bool {
    s.contains('@')
        || max_digit_run(s) >= 5
        || max_hex_run(s) >= 16
        || contains_uuid_substring(s)
}

fn looks_like_filename(s: &str) -> bool {
    match s.rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.is_empty()
                && (1..=5).contains(&ext.len())
                && ext.bytes().all(|b| b.is_ascii_alphanumeric())
        }
        None => false,
    }
}

fn has_unprintable(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn t(raw: &str) -> String {
        sanitize_path(raw).0
    }

    #[test]
    fn worked_examples_from_the_privacy_model() {
        assert_eq!(t("/v1/users/123456/orders/98765"), "/v1/users/:id/orders/:id");
        assert_eq!(
            t("/v1/files/550e8400-e29b-41d4-a716-446655440000"),
            "/v1/files/:uuid"
        );
        assert_eq!(
            t("/repos/octocat/hello/issues/42/comments"),
            "/repos/octocat/hello/issues/:id/comments"
        );
        assert_eq!(t("/users/alice@example.com/profile"), "/users/:email/profile");
        assert_eq!(t("/download/report_9f8e7d6c5b4a2210.csv"), "/download/:file");
        assert_eq!(t("/"), "/");
        assert_eq!(t("/v1/models"), "/v1/models");
    }

    #[test]
    fn query_and_fragment_are_severed() {
        let (out, _) = sanitize_path("/v1/users/42?token=SECRETVALUE&x=y#frag");
        assert_eq!(out, "/v1/users/:id");
        assert!(!out.contains("SECRET"));
        assert!(!out.contains('?'));
        assert!(!out.contains('#'));
    }

    #[test]
    fn credential_shaped_segments_are_tokenized() {
        assert_eq!(t("/callback/sk-proj-ABCDEFGHIJKLMNOP1234"), "/callback/:token");
        assert_eq!(
            t("/gh/ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            "/gh/:token"
        );
    }

    #[test]
    fn jwt_is_tokenized() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4";
        assert_eq!(t(&format!("/auth/{jwt}")), "/auth/:jwt");
    }

    #[test]
    fn kept_segments_are_low_entropy_structure() {
        assert_eq!(t("/api/v2/chat/completions"), "/api/v2/chat/completions");
        assert_eq!(t("/oauth2/token"), "/oauth2/token");
        assert_eq!(t("/s3/buckets"), "/s3/buckets");
        // sha256 keeps (digit run 3), logo.png keeps (no sensitive run)
        assert_eq!(t("/assets/logo.png"), "/assets/logo.png");
    }

    #[test]
    fn confidence_reflects_certainty() {
        assert_eq!(sanitize_path("/v1/users/:id").1, Confidence::High);
        assert_eq!(sanitize_path("/v1/users/123456").1, Confidence::High);
        // a bare high-entropy blob is a heuristic → Medium
        assert_eq!(
            sanitize_path("/x/Zm9vYmFyMTIzNDU2Nzg5MEFCQ0RFRg").1,
            Confidence::Medium
        );
        // not origin-form → Low
        assert_eq!(sanitize_path("garbage").1, Confidence::Low);
    }

    #[test]
    fn trailing_and_double_slashes_preserved() {
        assert_eq!(t("/v1/users/"), "/v1/users/");
        assert_eq!(t("/v1//users"), "/v1//users");
    }

    // --- Property tests (deterministic hand-rolled fuzz; no new dependency) --

    /// A large corpus of composed segments spanning every class, plus adversarial
    /// blobs. Used to assert the output invariants for thousands of inputs.
    fn fuzz_corpus() -> Vec<String> {
        let pieces = [
            "users", "v1", "v2", "orders", "chat", "completions", "models", "a", "ab",
            "123", "42", "123456", "98765432101234", "octocat", "hello-world",
            "550e8400-e29b-41d4-a716-446655440000",
            "9f8e7d6c5b4a32100ffeed", "deadbeefdeadbeefdeadbeef",
            "alice@example.com", "bob.smith@corp.co.uk",
            "sk-proj-ABCDEFGHIJKLMNOPqrstuvwx1234",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.QWERTYUIOP",
            "report_20240101_884213.pdf", "avatar_9f8e7d6c5b4a2210.png",
            "Zm9vYmFyMTIzNDU2Nzg5MEFCQ0RFRkdI", "café", "%E2%9C%93",
            "user_123456", "order-98765", "", "..", "a.b.c",
            "AKIAIOSFODNN7EXAMPLE", "xoxb-1234567890-abcdefghij",
        ];
        let mut out = Vec::new();
        for a in &pieces {
            for b in &pieces {
                out.push(format!("/{a}/{b}"));
                out.push(format!("/prefix/{a}/{b}/suffix"));
                // Distinctive canaries so we can prove nothing from the query
                // or fragment survives (a real path segment like "users" can
                // legitimately reappear; a canary cannot).
                out.push(format!("/{a}/{b}?q=QUERYCANARYZZ&secret=SECRETCANARYZZ#fragCANARYZZ"));
            }
        }
        out
    }

    #[test]
    fn property_no_query_or_fragment_survives() {
        for input in fuzz_corpus() {
            let (out, _) = sanitize_path(&input);
            assert!(!out.contains('?'), "P1 query leaked: {input} -> {out}");
            assert!(!out.contains('#'), "P1 fragment leaked: {input} -> {out}");
            // The query/fragment canaries must never reach the output.
            assert!(!out.contains("CANARYZZ"), "P1 tail leaked: {input} -> {out}");
        }
    }

    #[test]
    fn property_no_sensitive_runs_survive() {
        for input in fuzz_corpus() {
            let (out, _) = sanitize_path(&input);
            assert!(max_digit_run(&out) < 5, "P2 digit run: {input} -> {out}");
            assert!(max_hex_run(&out) < 16, "P3 hex run: {input} -> {out}");
            assert!(!contains_uuid_substring(&out), "P4 uuid: {input} -> {out}");
            assert!(!out.contains('@'), "P5 email: {input} -> {out}");
            // P6: every output segment is a placeholder or not high-entropy
            for seg in out.split('/') {
                if !seg.is_empty() && !seg.starts_with(':') && seg != "*" {
                    assert!(
                        !is_high_entropy(seg),
                        "P6 high-entropy segment survived: {input} -> {out} ({seg})"
                    );
                }
            }
        }
    }

    #[test]
    fn property_idempotent_and_bounded() {
        for input in fuzz_corpus() {
            let (out1, _c1) = sanitize_path(&input);
            let (out2, _c2) = sanitize_path(&out1);
            // Only the STRING is idempotent; confidence is a property of the
            // original input's certainty (a stored template is never
            // re-sanitized), so it is not asserted equal here.
            assert_eq!(out1, out2, "P7 not idempotent: {input}");
            assert!(out1.len() <= MAX_LEN + 16, "P8 length bound: {out1}");
            assert!(
                out1.split('/').count() <= MAX_PARTS + 2,
                "P8 part bound: {out1}"
            );
        }
    }

    #[test]
    fn very_long_path_is_truncated_low_confidence() {
        let long = format!("/{}", "seg/".repeat(60));
        let (out, conf) = sanitize_path(&long);
        assert!(out.contains(":truncated"));
        assert_eq!(conf, Confidence::Low);
    }

    #[test]
    fn control_characters_are_redacted() {
        let (out, conf) = sanitize_path("/v1/ab\u{0007}cd");
        assert_eq!(out, "/v1/:redacted");
        assert_eq!(conf, Confidence::Low);
    }
}
