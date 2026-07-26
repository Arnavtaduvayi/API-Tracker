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
    let cut = raw.find(['?', '#']).map(|i| &raw[..i]).unwrap_or(raw);

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
    if seg.len() > 40 || has_unprintable(seg) || has_encoded_control(seg) {
        return (":redacted".into(), Confidence::Low);
    }
    // Kept: a stable, low-entropy collection/resource name (users, v1, chat…).
    (seg.to_string(), Confidence::High)
}

fn is_hex_byte(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn is_uuid(s: &str) -> bool {
    is_uuid_bytes(s.as_bytes())
}

fn is_uuid_bytes(b: &[u8]) -> bool {
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
        Some((local, domain)) => {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        }
        None => false,
    }
}

/// Known credential/token prefixes. A path segment starting with one of these
/// is almost certainly a leaked secret in the URL and is replaced with `:token`.
const CREDENTIAL_PREFIXES: &[&str] = &[
    "sk-",
    "sk_",
    "pk_live",
    "pk_test",
    "rk_live",
    "rk_test",
    "whsec_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "glpat-",
    "shpat_",
    "shpss_",
    "shpca_",
    "Bearer",
    "eyJ",
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
        && parts
            .iter()
            .all(|p| p.len() >= 8 && is_base64url_charset(p))
}

/// Character-class diversity + length heuristic for opaque tokens.
///
/// The previous version required ≥3 character classes (or a ≥24-char base64url
/// blob that contained a digit), so opaque secrets with ≤2 classes and no digit
/// — e.g. a 22-char lowercase reset token, or a 20-char upper+lower camelCase
/// token — slipped through and were kept verbatim in stored path templates.
/// The rules below close that gap while staying conservative enough that real
/// low-entropy resource names (`completions`, `subscriptions`, …) are kept.
fn is_high_entropy(s: &str) -> bool {
    let n = s.len();
    if n < 16 {
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
    // ≥3 classes at ≥16 chars: an opaque mixed token (e.g. Ab3Xy9Qw2Lm5Zt8Nk).
    if classes >= 3 {
        return true;
    }
    // A base64url/alnum blob mixing letters and digits (2 classes), ≥20 chars.
    if is_base64url_charset(s) && digit && (lower || upper) && n >= 20 {
        return true;
    }
    // A single-class alphabetic blob, ≥16 chars, is opaque when it lacks the
    // vowel structure of a real word (random tokens have few vowels and long
    // consonant runs) or is simply longer than any real resource name (≥24).
    if classes == 1
        && (lower || upper)
        && n >= 16
        && (n >= 24 || vowel_ratio(s) < 0.20 || max_consonant_run(s) >= 6)
    {
        return true;
    }
    // A long two-class letters-only token (upper+lower, no digits/other), ≥20:
    // opaque camelCase token material rather than a readable segment name.
    if classes == 2 && lower && upper && !digit && !other && n >= 20 {
        return true;
    }
    false
}

fn is_vowel(b: u8) -> bool {
    matches!(
        b,
        b'a' | b'e' | b'i' | b'o' | b'u' | b'A' | b'E' | b'I' | b'O' | b'U'
    )
}

/// Fraction of ASCII-letter characters that are vowels (0.0 if no letters).
fn vowel_ratio(s: &str) -> f64 {
    let letters = s.bytes().filter(|b| b.is_ascii_alphabetic()).count();
    if letters == 0 {
        return 0.0;
    }
    let vowels = s.bytes().filter(|&b| is_vowel(b)).count();
    vowels as f64 / letters as f64
}

/// Longest run of consecutive non-vowel ASCII letters.
fn max_consonant_run(s: &str) -> usize {
    let mut best = 0;
    let mut cur = 0;
    for b in s.bytes() {
        if b.is_ascii_alphabetic() && !is_vowel(b) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

/// True if the segment contains a percent-encoded control byte (`%00`–`%1F` or
/// `%7F`). Such encodings never appear in legitimate structural path segments
/// and would otherwise smuggle raw control bytes past [`has_unprintable`], so
/// the segment is redacted rather than kept verbatim.
fn has_encoded_control(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i] == b'%' {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                let v = (h * 16 + l) as u8;
                if v < 0x20 || v == 0x7f {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
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
    // cheap scan: any 36-BYTE window that is a UUID. Operate on bytes so a
    // multibyte UTF-8 char in the segment can never trigger a char-boundary
    // slice panic (UUIDs are pure ASCII, so a byte window is exactly right).
    let b = s.as_bytes();
    if b.len() < 36 {
        return false;
    }
    (0..=b.len() - 36).any(|i| is_uuid_bytes(&b[i..i + 36]))
}

/// A segment that still embeds an identifier-shaped run and therefore must not
/// be kept verbatim.
fn has_embedded_sensitive(s: &str) -> bool {
    s.contains('@') || max_digit_run(s) >= 5 || max_hex_run(s) >= 16 || contains_uuid_substring(s)
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

/// Redact credential-shaped and high-entropy tokens from a command's argv
/// before it is persisted as a session's `command` label, so a secret passed as
/// an argument (`curl -H "Authorization: Bearer sk-live-…"`, `psql --password
/// …`, `…?api_key=sk-…`) is never stored in plaintext. Execution uses the raw
/// argv directly; only the stored/displayed label is redacted, so
/// over-redaction here is harmless.
pub fn redact_command(args: &[String]) -> String {
    let mut out: Vec<String> = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            out.push(":redacted".into());
            redact_next = false;
            continue;
        }
        let lower = arg.to_ascii_lowercase();
        // Flags whose FOLLOWING argument carries a secret value.
        if matches!(
            lower.as_str(),
            "-h" | "--header"
                | "-u"
                | "--user"
                | "--api-key"
                | "--apikey"
                | "--token"
                | "--password"
                | "--secret"
                | "--auth"
        ) {
            out.push(arg.clone());
            redact_next = true;
            continue;
        }
        out.push(redact_arg_token(arg));
    }
    out.join(" ")
}

/// Redact one argv token if any of its separated parts looks like a secret.
/// Splitting on URL/host separators (`/` and `.` included) breaks a normal URL
/// into short dictionary parts so it is not mistaken for a high-entropy token,
/// while a real embedded credential (`sk-…`, a JWT, an opaque blob) still stands
/// out as its own part.
fn redact_arg_token(arg: &str) -> String {
    let embeds_secret = arg
        .split(|c: char| {
            matches!(
                c,
                ' ' | ':' | '=' | '"' | '\'' | '&' | '?' | '@' | '/' | '.' | ',' | ';'
            )
        })
        .any(is_secretish);
    if embeds_secret {
        ":redacted".into()
    } else {
        arg.to_string()
    }
}

fn is_secretish(s: &str) -> bool {
    is_credential_shaped(s) || is_jwt(s) || (s.len() >= 20 && is_high_entropy(s))
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
        assert_eq!(
            t("/v1/users/123456/orders/98765"),
            "/v1/users/:id/orders/:id"
        );
        assert_eq!(
            t("/v1/files/550e8400-e29b-41d4-a716-446655440000"),
            "/v1/files/:uuid"
        );
        assert_eq!(
            t("/repos/octocat/hello/issues/42/comments"),
            "/repos/octocat/hello/issues/:id/comments"
        );
        assert_eq!(
            t("/users/alice@example.com/profile"),
            "/users/:email/profile"
        );
        assert_eq!(
            t("/download/report_9f8e7d6c5b4a2210.csv"),
            "/download/:file"
        );
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
        assert_eq!(
            t("/callback/sk-proj-ABCDEFGHIJKLMNOP1234"),
            "/callback/:token"
        );
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
            "users",
            "v1",
            "v2",
            "orders",
            "chat",
            "completions",
            "models",
            "a",
            "ab",
            "123",
            "42",
            "123456",
            "98765432101234",
            "octocat",
            "hello-world",
            "550e8400-e29b-41d4-a716-446655440000",
            "9f8e7d6c5b4a32100ffeed",
            "deadbeefdeadbeefdeadbeef",
            "alice@example.com",
            "bob.smith@corp.co.uk",
            "sk-proj-ABCDEFGHIJKLMNOPqrstuvwx1234",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.QWERTYUIOP",
            "report_20240101_884213.pdf",
            "avatar_9f8e7d6c5b4a2210.png",
            "Zm9vYmFyMTIzNDU2Nzg5MEFCQ0RFRkdI",
            "café",
            "%E2%9C%93",
            "user_123456",
            "order-98765",
            "",
            "..",
            "a.b.c",
            "AKIAIOSFODNN7EXAMPLE",
            "xoxb-1234567890-abcdefghij",
            // Opaque tokens with <=2 character classes and no digit/hex/uuid run
            // that older heuristics kept verbatim (PR-13 audit regressions).
            "xkqjwhdmzpvtrbnsgcfywq",        // 22 lowercase, single class
            "ghijklmnopqrstuvwxyzghijklmno", // 29 lowercase, single class
            "TokenValueSecretAbcdefg",       // 23 upper+lower, no digit
            "Ab3Xy9Qw2Lm5Zt8Nk",             // 18, three classes
            "cb/%73%65%63%72%65%74%41%42",   // percent-encoded (as one segment)
            "reset%00token",                 // encoded control byte
        ];
        let mut out = Vec::new();
        for a in &pieces {
            for b in &pieces {
                out.push(format!("/{a}/{b}"));
                out.push(format!("/prefix/{a}/{b}/suffix"));
                // Distinctive canaries so we can prove nothing from the query
                // or fragment survives (a real path segment like "users" can
                // legitimately reappear; a canary cannot).
                out.push(format!(
                    "/{a}/{b}?q=QUERYCANARYZZ&secret=SECRETCANARYZZ#fragCANARYZZ"
                ));
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
            assert!(
                !out.contains("CANARYZZ"),
                "P1 tail leaked: {input} -> {out}"
            );
        }
    }

    #[test]
    fn property_no_sensitive_runs_survive() {
        for input in fuzz_corpus() {
            let (out, _) = sanitize_path(&input);
            // P2–P5 use metrics independent of the classifier, so they can
            // genuinely fail if a sensitive run survives.
            assert!(max_digit_run(&out) < 5, "P2 digit run: {input} -> {out}");
            assert!(max_hex_run(&out) < 16, "P3 hex run: {input} -> {out}");
            assert!(!contains_uuid_substring(&out), "P4 uuid: {input} -> {out}");
            assert!(!out.contains('@'), "P5 email: {input} -> {out}");
            // P6 uses an INDEPENDENT oracle (Shannon entropy over the segment's
            // own byte distribution), NOT the production is_high_entropy — so
            // this test can fail if a real opaque secret is kept verbatim,
            // instead of being tautologically green. Any kept (non-placeholder)
            // segment long enough to matter must be low-entropy structure.
            for seg in out.split('/') {
                if !seg.is_empty() && !seg.starts_with(':') && seg != "*" && seg.len() >= 20 {
                    assert!(
                        shannon_bits_per_char(seg) < 4.0,
                        "P6 high-entropy segment survived: {input} -> {out} ({seg}, {:.2} bits/char)",
                        shannon_bits_per_char(seg)
                    );
                }
            }
        }
    }

    /// Independent high-entropy oracle for P6: Shannon entropy per character
    /// over the segment's own byte histogram. Deliberately does NOT call the
    /// production `is_high_entropy`, so the property test is not circular.
    fn shannon_bits_per_char(s: &str) -> f64 {
        use std::collections::HashMap;
        let mut counts: HashMap<u8, usize> = HashMap::new();
        for b in s.bytes() {
            *counts.entry(b).or_default() += 1;
        }
        let n = s.len() as f64;
        -counts
            .values()
            .map(|&c| {
                let p = c as f64 / n;
                p * p.log2()
            })
            .sum::<f64>()
    }

    #[test]
    fn opaque_tokens_are_never_kept_verbatim() {
        // Non-circular: assert the literal opaque token is absent from the
        // output (it was replaced by a placeholder). Covers the exact PR-13
        // audit examples: <=2 character classes / no digit, and 16–19 char
        // mixed tokens the length floor used to let through.
        let opaque = [
            "xkqjwhdmzpvtrbnsgcfywq",        // 22 lowercase
            "ghijklmnopqrstuvwxyzghijklmno", // 29 lowercase
            "TokenValueSecretAbcdefg",       // 23 upper+lower, no digit
            "Ab3Xy9Qw2Lm5Zt8Nk",             // 18, three classes
            "correcthorsebatterystaple",     // 25 lowercase
        ];
        for tok in opaque {
            let (out, _c) = sanitize_path(&format!("/api/{tok}/end"));
            assert!(
                !out.contains(tok),
                "opaque token kept verbatim: {tok} -> {out}"
            );
            assert_eq!(
                out, "/api/:token/end",
                "expected placeholder for {tok}: {out}"
            );
        }
        // Percent-encoded control bytes are redacted, not kept.
        let (out, _c) = sanitize_path("/cb/reset%00token");
        assert_eq!(out, "/cb/:redacted");
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
    fn redact_command_strips_secrets_from_argv() {
        let argv: Vec<String> = [
            "curl",
            "-H",
            "Authorization: Bearer sk-live-REALKEY0000000000",
            "https://api.stripe.com/v1/charges",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let label = redact_command(&argv);
        assert!(
            !label.contains("sk-live-REALKEY0000000000"),
            "token leaked: {label}"
        );
        assert!(
            !label.contains("Bearer"),
            "header value not redacted: {label}"
        );
        assert!(label.starts_with("curl -H :redacted"));
        // The non-secret URL is preserved.
        assert!(label.contains("https://api.stripe.com/v1/charges"));

        // Secret embedded in a URL query is redacted (whole token).
        let argv2: Vec<String> = [
            "wget",
            "https://api.example.com/data?api_key=sk-proj-ABCDEFGH12345678",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let label2 = redact_command(&argv2);
        assert!(
            !label2.contains("sk-proj-ABCDEFGH12345678"),
            "query secret leaked: {label2}"
        );

        // A plain, secret-free command is untouched.
        let argv3: Vec<String> = ["node", "server.js", "--port", "3000"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(redact_command(&argv3), "node server.js --port 3000");
    }

    #[test]
    fn control_characters_are_redacted() {
        let (out, conf) = sanitize_path("/v1/ab\u{0007}cd");
        assert_eq!(out, "/v1/:redacted");
        assert_eq!(conf, Confidence::Low);
    }
}
