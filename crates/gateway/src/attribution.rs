//! Credential attribution by keyed fingerprint (ADR 0019 D5).
//!
//! The gateway is the terminating server for a request that carries the
//! caller's own credential, so the value is unavoidably in its memory for the
//! duration of the forward. This module is the ONLY place that value is read,
//! and it does exactly six things, in order:
//!
//! 1. isolate the credential value from a recognized header,
//! 2. normalize it (scheme strip + trim, matching what the vault stored),
//! 3. compute `blake3::keyed_hash` under the vault's fingerprint key —
//!    the exact `core::reuse::fingerprint` construction (ADR 0005),
//! 4. compare (constant-time) against stored fingerprints, on the WRITER
//!    thread — never on the forwarding path,
//! 5. persist only attribution METADATA (a state label and, on a match, a
//!    credential id),
//! 6. zeroize every temporary.
//!
//! The original provider header is forwarded byte-for-byte untouched: nothing
//! here mutates the request.
//!
//! **There is no unkeyed-hash fallback.** A plain `blake3::hash(value)` would
//! turn a stolen database into an offline guess-confirmation oracle; the
//! keyed construction is the whole point of ADR 0005, and a source-level test
//! pins that no such fallback exists.

use api_tracker_core::error::Result;
use api_tracker_core::runtime::model::AttributionConfidence;
use api_tracker_core::secret::{SecretBytes, SecretString};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::head::RequestHead;
use crate::record::{AttributionInput, CredentialDigest};

/// Header names whose values are recognized credential locations. Nothing
/// else is ever read: no body scanning, no query scanning, no cookie
/// scanning (PRIVACY_MODEL §4).
pub const CREDENTIAL_HEADERS: &[&str] =
    &["authorization", "x-api-key", "api-key", "x-goog-api-key"];

/// Auth schemes whose token is the credential value. `Basic` is deliberately
/// absent: its value is base64(user:pass), not a stored credential value, so
/// it is reported as an unsupported form rather than mis-hashed.
const STRIPPABLE_SCHEMES: &[&str] = &["bearer", "token"];

/// The maximum credential-value length considered. Longer values are not
/// credentials Tethra stores, and bounding this keeps a hostile header from
/// making the gateway hash megabytes per request.
pub const MAX_CREDENTIAL_LEN: usize = 8 * 1024;

/// The candidate normalized forms of one presented header value.
///
/// Both are tried because the two storage conventions differ: the vault's
/// fingerprint is over the value the user SAVED (`sk-...`), while the wire
/// carries `Authorization: Bearer sk-...`. Without the scheme strip every
/// Bearer request would falsely report `unmatched` — a permanent false
/// "shadow credential" alarm (the Phase 1 review's finding).
fn candidates(value: &str) -> Vec<Zeroizing<String>> {
    let trimmed = value.trim();
    let mut out: Vec<Zeroizing<String>> = Vec::with_capacity(2);
    for scheme in STRIPPABLE_SCHEMES {
        let n = scheme.len();
        if trimmed.len() > n
            && trimmed[..n].eq_ignore_ascii_case(scheme)
            && trimmed.as_bytes()[n].is_ascii_whitespace()
        {
            let rest = trimmed[n..].trim();
            if !rest.is_empty() {
                out.push(Zeroizing::new(rest.to_string()));
            }
        }
    }
    out.push(Zeroizing::new(trimmed.to_string()));
    out
}

/// Whether a presented `Authorization` value uses a scheme this version does
/// not support (v1: `Basic`, plus anything else scheme-shaped that is not
/// Bearer/Token).
fn is_unsupported_scheme(value: &str) -> bool {
    const KNOWN_SCHEMES: &[&str] = &[
        "bearer",
        "token",
        "basic",
        "digest",
        "negotiate",
        "ntlm",
        "hoba",
        "mutual",
        "aws4-hmac-sha256",
    ];
    let trimmed = value.trim();
    let Some((scheme, rest)) = trimmed.split_once(char::is_whitespace) else {
        // A bare token IS supported — unless it is nothing but a scheme name
        // with no credential after it, which is not a credential at all.
        return KNOWN_SCHEMES
            .iter()
            .any(|s| trimmed.eq_ignore_ascii_case(s));
    };
    if rest.trim().is_empty() {
        return true;
    }
    !STRIPPABLE_SCHEMES
        .iter()
        .any(|s| scheme.eq_ignore_ascii_case(s))
}

/// Compute the transient keyed digest of whatever credential the request
/// presented. Returns the digest and the honest reason when there is none.
///
/// The value is borrowed from the head's `Zeroizing` buffer, copied only into
/// `Zeroizing` temporaries, hashed, and dropped before this function returns.
/// It is never stored, never logged, never queued.
pub fn digest_request(
    key: Option<&SecretBytes>,
    head: &RequestHead,
) -> (AttributionInput, Option<CredentialDigest>) {
    // EVERY recognized credential header is considered, not just the first.
    // Real clients send more than one: an Anthropic client configured with
    // both an auth token and an API key sends `Authorization` AND
    // `x-api-key`; Azure-style clients send `api-key` alongside an
    // `Authorization: Bearer <AAD JWT>`. Taking only the first would digest
    // the wrong bytes and report a false `unmatched` — a permanent phantom
    // shadow-credential alarm — for the credential that actually served the
    // request.
    let fields: Vec<&crate::head::HeaderField> = head
        .headers
        .iter()
        .filter(|h| CREDENTIAL_HEADERS.contains(&h.lower.as_str()))
        .collect();
    if fields.is_empty() {
        return (AttributionInput::NoCredentialPresent, None);
    }
    // No key in memory: the vault is locked (or the match-while-locked toggle
    // is off). Recorded as its OWN state — never as `unmatched`.
    let Some(key) = key else {
        return (AttributionInput::UnavailableNoKey, None);
    };
    let Ok(key32) = <&[u8; 32]>::try_from(key.expose()) else {
        return (AttributionInput::UnavailableNoKey, None);
    };

    let mut digests: Vec<[u8; 32]> = Vec::with_capacity(4);
    let mut saw_unsupported = false;
    for field in fields {
        let Some(value) = field.value_str() else {
            saw_unsupported = true;
            continue;
        };
        if value.trim().is_empty() || value.len() > MAX_CREDENTIAL_LEN {
            saw_unsupported = true;
            continue;
        }
        if field.lower == "authorization" && is_unsupported_scheme(value) {
            // `Basic` and unknown schemes are out of scope v1; reporting one
            // as "unmatched" would be a false shadow-credential alarm. It
            // must NOT stop the other headers from being considered.
            saw_unsupported = true;
            continue;
        }
        for candidate in candidates(value) {
            // Byte-identical to core::reuse::fingerprint (trim + keyed_hash),
            // cross-checked by test.
            let digest = *blake3::keyed_hash(key32, candidate.trim().as_bytes()).as_bytes();
            if !digests.contains(&digest) {
                digests.push(digest);
            }
        }
    }
    if digests.is_empty() {
        return (
            if saw_unsupported {
                AttributionInput::UnsupportedForm
            } else {
                AttributionInput::NoCredentialPresent
            },
            None,
        );
    }
    (
        AttributionInput::Digested,
        Some(CredentialDigest {
            candidates: digests,
        }),
    )
}

/// One credential's public fingerprint row, as pushed into the matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintEntry {
    /// The ROOT credential id: references are collapsed to the value-bearing
    /// record, so the vault's own recommended sharing model does not force a
    /// permanent `ambiguous_duplicate`.
    pub credential_id: String,
    pub fingerprint: Vec<u8>,
    /// `Some(version)` when this fingerprint belongs to a RETAINED
    /// pre-rotation version rather than the current value.
    pub retained_version: Option<i64>,
    pub current_version: Option<i64>,
    /// A credential the user marked revoked/disabled: still matched (the
    /// traffic is real and worth surfacing), but flagged.
    pub revoked: bool,
}

/// The resolved attribution of one exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    /// Exactly one independent credential matched its current value.
    Matched {
        credential_id: String,
        revoked: bool,
    },
    /// A still-deployed PRE-ROTATION version matched — distinct from
    /// `Unmatched`, which would have hidden a real rotation gap.
    MatchedOldVersion {
        credential_id: String,
        version: i64,
    },
    /// The same value belongs to several INDEPENDENT credentials; none is
    /// chosen and no `last_used_at` is bumped.
    AmbiguousDuplicate {
        credential_ids: Vec<String>,
    },
    /// A credential was presented and digested, but no stored fingerprint
    /// matched — an honest "shadow credential" signal.
    Unmatched,
    NoCredentialPresent,
    /// No recognized credential form (Basic, query- or cookie-borne).
    UnsupportedForm,
    /// No matching key in memory. NEVER conflated with `Unmatched`, and
    /// never retroactively rewritten: values are not retained, so post-unlock
    /// re-attribution of past events is impossible by design.
    UnavailableNoKey,
}

impl Attribution {
    /// The DB label for the attribution state.
    pub fn as_str(&self) -> &'static str {
        match self {
            Attribution::Matched { .. } => "matched",
            Attribution::MatchedOldVersion { .. } => "matched_old_version",
            Attribution::AmbiguousDuplicate { .. } => "ambiguous_duplicate",
            Attribution::Unmatched => "unmatched",
            Attribution::NoCredentialPresent => "no_credential_present",
            Attribution::UnsupportedForm => "unsupported_form",
            // The gateway cannot see vault state: this is produced purely from
            // "no matching key is resident", which is ALSO the default state
            // right after startup with the vault wide open. `unavailable_no_key`
            // is what the code can actually attest to.
            Attribution::UnavailableNoKey => "unavailable_no_key",
        }
    }

    /// The credential id to record, when exactly one was identified.
    pub fn credential_id(&self) -> Option<&str> {
        match self {
            Attribution::Matched { credential_id, .. }
            | Attribution::MatchedOldVersion { credential_id, .. } => Some(credential_id),
            _ => None,
        }
    }

    /// The runtime confidence label. Value-derived matches use the distinct
    /// `MatchedFingerprint` label so they are never conflated with
    /// injection-derived attribution.
    pub fn confidence(&self) -> AttributionConfidence {
        match self {
            Attribution::Matched { .. } | Attribution::MatchedOldVersion { .. } => {
                AttributionConfidence::MatchedFingerprint
            }
            Attribution::AmbiguousDuplicate { .. } => AttributionConfidence::Ambiguous,
            _ => AttributionConfidence::Unattributed,
        }
    }

    /// Whether `credentials.last_used_at` should be bumped. Only a single
    /// confirmed match does: an ambiguous set proves nothing about which
    /// credential was used.
    pub fn bumps_last_used(&self) -> bool {
        matches!(
            self,
            Attribution::Matched { .. } | Attribution::MatchedOldVersion { .. }
        )
    }
}

/// The provenance column value for value-derived rows.
pub const METHOD_OBSERVED_FINGERPRINT: &str = "observed_fingerprint";

/// The scoped matcher table: fingerprints of credentials in LINKED,
/// non-password-locked projects only.
///
/// It is never vault-wide. A vault-wide resident table would let any local
/// process confirm guessed values against every credential — including
/// password-locked projects — while the vault is locked (the Phase 1
/// online-oracle blocker, THREAT_MODEL GW-6).
#[derive(Debug, Default, Clone)]
pub struct Matcher {
    entries: Vec<FingerprintEntry>,
}

impl Matcher {
    pub fn new(entries: Vec<FingerprintEntry>) -> Self {
        Self { entries }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve a digest against the table. Runs on the WRITER thread, so no
    /// forwarding-path timing depends on whether a credential matched; the
    /// comparison itself is still constant-time.
    pub fn resolve(&self, digest: &CredentialDigest) -> Attribution {
        for candidate in &digest.candidates {
            let hits: Vec<&FingerprintEntry> = self
                .entries
                .iter()
                .filter(|e| {
                    e.fingerprint.len() == 32
                        && e.fingerprint[..].ct_eq(&candidate[..]).unwrap_u8() == 1
                })
                .collect();
            if hits.is_empty() {
                continue;
            }
            // References were collapsed to their root before the table was
            // built, so distinct ids here are genuinely independent
            // credentials.
            let mut ids: Vec<String> = hits.iter().map(|e| e.credential_id.clone()).collect();
            ids.sort();
            ids.dedup();
            if ids.len() > 1 {
                return Attribution::AmbiguousDuplicate {
                    credential_ids: ids,
                };
            }
            let hit = hits[0];
            return match hit.retained_version {
                Some(version) => Attribution::MatchedOldVersion {
                    credential_id: hit.credential_id.clone(),
                    version,
                },
                None => Attribution::Matched {
                    credential_id: hit.credential_id.clone(),
                    revoked: hit.revoked,
                },
            };
        }
        Attribution::Unmatched
    }
}

/// Build the scoped matcher table from a vault database.
///
/// Scoping rules, all load-bearing:
/// - only credentials of projects with a live `gateway_project_links` row,
/// - excluding password-locked projects (`key_wrap_mode = 'vault+password'`)
///   BOTH where the row itself lives and where its ROOT lives — a reference
///   row in an unlocked project carries a COPY of the root's fingerprint, so
///   filtering only on the row's own project would let a password-locked
///   project's credential become oracle-confirmable through a reference
///   (SI-9, THREAT_MODEL GW-6). The cost is honest: traffic using such a
///   shared value reports `unmatched` until the owning project is unlocked.
/// - references collapsed to their root credential id,
/// - retained pre-rotation versions included, flagged as such.
pub fn load_matcher_table(conn: &rusqlite::Connection) -> Result<Vec<FingerprintEntry>> {
    let mut entries = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT COALESCE(c.linked_credential_id, c.id) AS root_id,
                c.fingerprint, c.value_version,
                (c.revoked = 1 OR c.manually_disabled = 1) AS revoked
         FROM credentials c
         JOIN projects p ON p.id = c.project_id
         WHERE p.key_wrap_mode <> 'vault+password'
           AND EXISTS (SELECT 1 FROM gateway_project_links g
                       WHERE g.project_id = c.project_id)
           AND NOT EXISTS (
                 SELECT 1
                 FROM credentials root
                 JOIN projects rp ON rp.id = root.project_id
                 WHERE root.id = c.linked_credential_id
                   AND rp.key_wrap_mode = 'vault+password'
               )",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(FingerprintEntry {
            credential_id: r.get(0)?,
            fingerprint: r.get(1)?,
            retained_version: None,
            current_version: r.get(2)?,
            revoked: r.get::<_, i64>(3)? != 0,
        })
    })?;
    for row in rows {
        entries.push(row?);
    }

    // Retained pre-rotation versions: a still-deployed old key must report
    // `matched_old_version`, not `unmatched`.
    // Retained versions belong to the ROOT credential, but the root may live
    // in a project that is not itself linked while a REFERENCE to it is. The
    // scoping question is "is this value in scope for some linked,
    // non-password-locked project?", so the check follows the reference the
    // same way the current-value query does: a version is in scope if the
    // root OR any reference to it sits in a linked, unlocked project.
    let mut stmt = conn.prepare(
        "SELECT v.credential_id AS root_id, v.fingerprint, v.version, c.value_version
         FROM credential_versions v
         JOIN credentials c ON c.id = v.credential_id
         JOIN projects rp ON rp.id = c.project_id
         WHERE rp.key_wrap_mode <> 'vault+password'
           AND EXISTS (
                 SELECT 1
                 FROM credentials ref
                 JOIN projects p ON p.id = ref.project_id
                 JOIN gateway_project_links g ON g.project_id = ref.project_id
                 WHERE (ref.id = v.credential_id
                        OR ref.linked_credential_id = v.credential_id)
                   AND p.key_wrap_mode <> 'vault+password'
               )",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(FingerprintEntry {
            credential_id: r.get(0)?,
            fingerprint: r.get(1)?,
            retained_version: Some(r.get(2)?),
            current_version: r.get(3)?,
            revoked: false,
        })
    })?;
    for row in rows {
        let entry = row?;
        // A retained version whose fingerprint equals the current one is not
        // an "old version" in any meaningful sense.
        if entries
            .iter()
            .any(|e| e.credential_id == entry.credential_id && e.fingerprint == entry.fingerprint)
        {
            continue;
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Verify at runtime that this build's digest equals `core::reuse::fingerprint`
/// for a given value. Used by tests to pin the constructions together.
#[doc(hidden)]
pub fn core_fingerprint_for_test(key: &SecretBytes, value: &str) -> Result<Vec<u8>> {
    api_tracker_core::reuse::fingerprint(key, &SecretString::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretBytes {
        SecretBytes::new(vec![7u8; 32])
    }

    fn fp(k: &SecretBytes, v: &str) -> Vec<u8> {
        core_fingerprint_for_test(k, v).unwrap()
    }

    fn head_with(name: &str, value: &str) -> RequestHead {
        let raw = format!("GET /openai/v1/x HTTP/1.1\r\nHost: h\r\n{name}: {value}\r\n\r\n");
        let mut c = std::io::Cursor::new(raw.into_bytes());
        crate::head::read_request_head(&mut c, Zeroizing::new(Vec::new()), None)
            .unwrap()
            .unwrap()
            .0
    }

    #[test]
    fn the_digest_is_byte_identical_to_cores_keyed_fingerprint() {
        let k = key();
        let value = "FAKE-TEST-NOT-A-REAL-KEY-AAAA";
        let head = head_with("x-api-key", value);
        let (input, digest) = digest_request(Some(&k), &head);
        assert_eq!(input, AttributionInput::Digested);
        let digest = digest.unwrap();
        assert!(
            digest.candidates.iter().any(|c| c[..] == fp(&k, value)[..]),
            "the gateway digest must equal core::reuse::fingerprint"
        );
    }

    #[test]
    fn a_bearer_header_matches_a_fingerprint_stored_over_the_bare_value() {
        let k = key();
        let value = "FAKE-TEST-NOT-A-REAL-KEY-AAAA";
        let table = Matcher::new(vec![FingerprintEntry {
            credential_id: "cred-a".into(),
            fingerprint: fp(&k, value),
            retained_version: None,
            current_version: Some(1),
            revoked: false,
        }]);
        for header in [
            format!("Bearer {value}"),
            format!("bearer   {value}"),
            format!("Token {value}"),
            format!("  Bearer {value}  "),
        ] {
            let head = head_with("authorization", &header);
            let (_, digest) = digest_request(Some(&k), &head);
            assert_eq!(
                table.resolve(&digest.unwrap()),
                Attribution::Matched {
                    credential_id: "cred-a".into(),
                    revoked: false
                },
                "the scheme token must be stripped before hashing: {header:?}"
            );
        }
    }

    #[test]
    fn every_attribution_state_is_distinct_and_honest() {
        let k = key();
        let a = "FAKE-TEST-NOT-A-REAL-KEY-AAAA";
        let b = "FAKE-TEST-NOT-A-REAL-KEY-BBBB";
        let old = "FAKE-TEST-NOT-A-REAL-KEY-OLD0";
        let table = Matcher::new(vec![
            FingerprintEntry {
                credential_id: "cred-a".into(),
                fingerprint: fp(&k, a),
                retained_version: None,
                current_version: Some(2),
                revoked: false,
            },
            FingerprintEntry {
                credential_id: "cred-a".into(),
                fingerprint: fp(&k, old),
                retained_version: Some(1),
                current_version: Some(2),
                revoked: false,
            },
            FingerprintEntry {
                credential_id: "cred-b1".into(),
                fingerprint: fp(&k, b),
                retained_version: None,
                current_version: Some(1),
                revoked: false,
            },
            FingerprintEntry {
                credential_id: "cred-b2".into(),
                fingerprint: fp(&k, b),
                retained_version: None,
                current_version: Some(1),
                revoked: false,
            },
        ]);
        let resolve = |value: &str| {
            let head = head_with("x-api-key", value);
            let (_, d) = digest_request(Some(&k), &head);
            table.resolve(&d.unwrap())
        };

        assert_eq!(
            resolve(a),
            Attribution::Matched {
                credential_id: "cred-a".into(),
                revoked: false
            }
        );
        assert_eq!(
            resolve(old),
            Attribution::MatchedOldVersion {
                credential_id: "cred-a".into(),
                version: 1
            },
            "a still-deployed pre-rotation value is not `unmatched`"
        );
        match resolve(b) {
            Attribution::AmbiguousDuplicate { credential_ids } => {
                assert_eq!(credential_ids, vec!["cred-b1", "cred-b2"]);
            }
            other => panic!("expected ambiguous, got {other:?}"),
        }
        assert_eq!(
            resolve("FAKE-TEST-NOT-A-REAL-KEY-ZZZZ"),
            Attribution::Unmatched
        );

        // Trim semantics match core's (trailing whitespace does not defeat it).
        assert_eq!(
            resolve(&format!("{a}  ")),
            Attribution::Matched {
                credential_id: "cred-a".into(),
                revoked: false
            }
        );

        // No credential at all.
        let bare = {
            let raw = "GET /openai/v1/x HTTP/1.1\r\nHost: h\r\n\r\n";
            let mut c = std::io::Cursor::new(raw.as_bytes().to_vec());
            crate::head::read_request_head(&mut c, Zeroizing::new(Vec::new()), None)
                .unwrap()
                .unwrap()
                .0
        };
        assert_eq!(
            digest_request(Some(&k), &bare).0,
            AttributionInput::NoCredentialPresent
        );

        // Locked vault: its own state, never `unmatched`.
        let head = head_with("x-api-key", a);
        assert_eq!(
            digest_request(None, &head).0,
            AttributionInput::UnavailableNoKey
        );
    }

    #[test]
    fn unsupported_credential_forms_are_labeled_not_mis_hashed() {
        let k = key();
        for value in [
            "Basic ZmFrZTpmYWtl",
            "Digest username=\"x\"",
            "Negotiate abcdef",
            "Bearer ",
        ] {
            let head = head_with("authorization", value);
            let (input, digest) = digest_request(Some(&k), &head);
            assert_eq!(
                input,
                AttributionInput::UnsupportedForm,
                "{value:?} must be labeled unsupported"
            );
            assert!(digest.is_none());
        }
        // An oversized header value is not hashed at all.
        let head = head_with("x-api-key", &"a".repeat(MAX_CREDENTIAL_LEN + 1));
        assert_eq!(
            digest_request(Some(&k), &head).0,
            AttributionInput::UnsupportedForm
        );
    }

    #[test]
    fn revoked_credentials_still_match_but_are_flagged() {
        let k = key();
        let v = "FAKE-TEST-NOT-A-REAL-KEY-REVOKED";
        let table = Matcher::new(vec![FingerprintEntry {
            credential_id: "cred-r".into(),
            fingerprint: fp(&k, v),
            retained_version: None,
            current_version: Some(1),
            revoked: true,
        }]);
        let head = head_with("x-api-key", v);
        let (_, d) = digest_request(Some(&k), &head);
        assert_eq!(
            table.resolve(&d.unwrap()),
            Attribution::Matched {
                credential_id: "cred-r".into(),
                revoked: true
            },
            "traffic using a revoked credential is real and must be surfaced"
        );
    }

    #[test]
    fn attribution_labels_and_last_used_semantics_are_stable() {
        assert_eq!(
            Attribution::Matched {
                credential_id: "c".into(),
                revoked: false
            }
            .as_str(),
            "matched"
        );
        assert_eq!(
            Attribution::MatchedOldVersion {
                credential_id: "c".into(),
                version: 1
            }
            .as_str(),
            "matched_old_version"
        );
        assert_eq!(
            Attribution::AmbiguousDuplicate {
                credential_ids: vec![]
            }
            .as_str(),
            "ambiguous_duplicate"
        );
        assert_eq!(Attribution::Unmatched.as_str(), "unmatched");
        assert_eq!(
            Attribution::NoCredentialPresent.as_str(),
            "no_credential_present"
        );
        assert_eq!(Attribution::UnsupportedForm.as_str(), "unsupported_form");
        assert_eq!(
            Attribution::UnavailableNoKey.as_str(),
            "unavailable_no_key",
            "the gateway cannot observe vault state; the label must say what \
             the code actually knows (no resident matching key), which is also \
             the state right after startup with the vault wide open"
        );

        // Only a single confirmed match bumps last_used_at.
        assert!(Attribution::Matched {
            credential_id: "c".into(),
            revoked: false
        }
        .bumps_last_used());
        assert!(!Attribution::AmbiguousDuplicate {
            credential_ids: vec!["a".into(), "b".into()]
        }
        .bumps_last_used());
        assert!(!Attribution::Unmatched.bumps_last_used());
        assert!(!Attribution::UnavailableNoKey.bumps_last_used());

        // Value-derived confidence is its own label.
        assert_eq!(
            Attribution::Matched {
                credential_id: "c".into(),
                revoked: false
            }
            .confidence(),
            AttributionConfidence::MatchedFingerprint
        );
    }

    #[test]
    fn the_digest_debug_never_prints_a_digest_or_a_value() {
        let k = key();
        let value = "FAKE-TEST-NOT-A-REAL-KEY-AAAA";
        let head = head_with("authorization", &format!("Bearer {value}"));
        let (_, digest) = digest_request(Some(&k), &head);
        let printed = format!("{:?}", digest.unwrap());
        assert!(!printed.contains(value));
        assert!(!printed.contains("FAKE"));
        // The head's own Debug must not print the header value either.
        let head_printed = format!("{head:?}");
        assert!(!head_printed.contains(value));
    }
}

#[cfg(test)]
mod multi_header_tests {
    use super::*;

    fn key() -> SecretBytes {
        SecretBytes::new(vec![7u8; 32])
    }

    fn head_with(headers: &[(&str, &str)]) -> RequestHead {
        let mut raw = String::from("GET /openai/v1/x HTTP/1.1\r\nHost: h\r\n");
        for (name, value) in headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        raw.push_str("\r\n");
        let mut c = std::io::Cursor::new(raw.into_bytes());
        crate::head::read_request_head(&mut c, Zeroizing::new(Vec::new()), None)
            .unwrap()
            .unwrap()
            .0
    }

    /// A client sending BOTH an Authorization header and an x-api-key must
    /// have both digested: taking only the first would report a false
    /// `unmatched` for whichever one the provider actually honored.
    #[test]
    fn every_recognized_credential_header_is_digested() {
        let k = key();
        let bearer = "FAKE-TEST-NOT-A-REAL-KEY-BEARER";
        let apikey = "FAKE-TEST-NOT-A-REAL-KEY-XAPIKEY";
        let table = Matcher::new(vec![FingerprintEntry {
            credential_id: "cred-x".into(),
            fingerprint: core_fingerprint_for_test(&k, apikey).unwrap(),
            retained_version: None,
            current_version: Some(1),
            revoked: false,
        }]);
        // Authorization comes FIRST on the wire; the match is on x-api-key.
        let head = head_with(&[
            ("Authorization", &format!("Bearer {bearer}")),
            ("x-api-key", apikey),
        ]);
        let (input, digest) = digest_request(Some(&k), &head);
        assert_eq!(input, AttributionInput::Digested);
        assert_eq!(
            table.resolve(&digest.unwrap()),
            Attribution::Matched {
                credential_id: "cred-x".into(),
                revoked: false
            },
            "the second credential header must still be considered"
        );
    }

    /// A leading `Basic` (unsupported) must not hide a following supported
    /// header.
    #[test]
    fn an_unsupported_leading_scheme_does_not_mask_a_later_credential() {
        let k = key();
        let apikey = "FAKE-TEST-NOT-A-REAL-KEY-BEHIND-BASIC";
        let table = Matcher::new(vec![FingerprintEntry {
            credential_id: "cred-y".into(),
            fingerprint: core_fingerprint_for_test(&k, apikey).unwrap(),
            retained_version: None,
            current_version: Some(1),
            revoked: false,
        }]);
        let head = head_with(&[
            ("Authorization", "Basic ZmFrZTpmYWtl"),
            ("x-api-key", apikey),
        ]);
        let (input, digest) = digest_request(Some(&k), &head);
        assert_eq!(input, AttributionInput::Digested);
        assert_eq!(
            table.resolve(&digest.unwrap()),
            Attribution::Matched {
                credential_id: "cred-y".into(),
                revoked: false
            }
        );
    }

    /// When EVERY recognized header is unsupported, the honest answer is
    /// still `unsupported_form`, not `unmatched`.
    #[test]
    fn all_unsupported_headers_still_report_unsupported_form() {
        let k = key();
        let head = head_with(&[("Authorization", "Basic ZmFrZTpmYWtl")]);
        let (input, digest) = digest_request(Some(&k), &head);
        assert_eq!(input, AttributionInput::UnsupportedForm);
        assert!(digest.is_none());
    }

    /// A locked vault still short-circuits before any hashing, whatever the
    /// header mix.
    #[test]
    fn a_locked_vault_short_circuits_regardless_of_header_count() {
        let head = head_with(&[
            ("Authorization", "Bearer FAKE-TEST-NOT-A-REAL-KEY-A"),
            ("x-api-key", "FAKE-TEST-NOT-A-REAL-KEY-B"),
        ]);
        assert_eq!(
            digest_request(None, &head).0,
            AttributionInput::UnavailableNoKey
        );
    }
}
