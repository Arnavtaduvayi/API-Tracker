//! NEW-49 / SEC-01 — the shipping documents must not re-acquire the security
//! guarantee this product does not have.
//!
//! ## The finding this pins
//!
//! `crates/gateway/src/routes.rs` resolves a built-in (manifest) route through
//! `providers::find(&provider_id)` with `provider_id` read straight from the
//! untrusted `gateway_routes` row. `route_mac` is verified only for rows still
//! shaped as custom rows. So an attacker who can already write `vault.db` can
//! `UPDATE gateway_routes SET provider_id='anthropic' WHERE route_prefix='openai'`
//! and send the user's OpenAI credential to `api.anthropic.com`, and can null
//! the four custom columns together to downgrade a MAC'd custom route onto that
//! same unauthenticated path.
//!
//! That is an **accepted** risk: it requires local write access to the vault
//! database, which the root `THREAT_MODEL.md` excludes. Accepted risk is only
//! legitimate while it is honestly disclosed — and the disclosure was
//! contradicted in eight shipping places, including a `SECURITY.md` heading
//! that read "Why database tampering cannot redirect your credentials". This
//! test is the standing guard on that disclosure.
//!
//! It deliberately does NOT flatten two different things into one. Injecting an
//! attacker-chosen destination into the route table is prevented; reassigning a
//! route among origins Tethra already ships is not. The documents keep that
//! distinction, so this test only forbids the absolute claim.
//!
//! ## Why a repository scan, and why here
//!
//! A grep is a blunt instrument, but it is the instrument that would have
//! caught this — the same reasoning as
//! `legacy_rollback_migration.rs::both_front_ends_call_the_shared_migration`,
//! which likewise walks up to the repo root and reads files outside this crate.
//! The false claims lived in seven `docs/` files and one `.tsx` string; no unit
//! test can observe a document. CI already runs `cargo test -p
//! api-tracker-gateway` on Linux and Windows, so this needs no CI change.
//!
//! ## What is excluded from the scan, and why
//!
//! * **Per-audit artifact directories under `docs/activity-onboarding/audit/`**
//!   (e.g. `opus-fresh-final-20260729/`, `fable-independent-20260727/`) — each
//!   directory is one independent audit's evidence bundle, named for the audit
//!   that produced it. Those reports quote the false claims *verbatim* because
//!   quoting them is the finding. They are historical evidence, they are
//!   read-only, and editing them to satisfy a build would be tampering with the
//!   record. Loose files directly in `docs/activity-onboarding/audit/` are NOT
//!   excluded — they are living remediation matrices, not frozen evidence.
//! * **Test files** (`tests/` directories, `*.test.*`, `*.spec.*`, including
//!   this file) — a test that pins the ABSENCE of a sentence must contain the
//!   sentence. Excluding them is what makes the scanner able to state its own
//!   deny list.
//! * `.git`, `node_modules`, `target`, and other build output.
//!
//! Non-text files are never opened: only a whitelist of source/prose extensions
//! is read, and anything over `MAX_FILE_BYTES` is skipped, so the scan stays
//! fast and never touches a binary.

use std::fs;
use std::path::{Path, PathBuf};

/// Extensions worth reading. An extension whitelist (rather than a
/// binary-sniff) is what keeps this from ever opening an image or a database.
const SCANNED_EXTENSIONS: &[&str] = &[
    "md", "rs", "ts", "tsx", "js", "jsx", "txt", "toml", "json", "yml", "yaml", "sh", "html",
    "css", "rst",
];

/// Directory names that never contain a product claim.
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "coverage",
    ".venv",
    ".next",
    ".vite",
    ".idea",
];

/// Big files are lockfiles and generated data, not prose. Skipping them keeps
/// the whole scan well under a second.
const MAX_FILE_BYTES: u64 = 512 * 1024;

/// A sentence that asserts more protection than the code provides.
struct DenyPhrase {
    /// Matched against whitespace-normalised, lowercased text.
    phrase: &'static str,
    /// If non-empty, the file must also mention one of these for the phrase to
    /// count — keeps generic English out of unrelated documents.
    requires_any: &'static [&'static str],
    /// What is actually true, quoted back to whoever trips this.
    why: &'static str,
}

/// The claims NEW-49 removed. Each is the *absolute* form; the scoped forms
/// ("cannot redirect a MAC'd custom route", "cannot send a credential to an
/// attacker-chosen origin") are true and are deliberately not listed.
const DENIED: &[DenyPhrase] = &[
    DenyPhrase {
        phrase: "tampering cannot redirect",
        requires_any: &[],
        why: "database tampering CAN redirect a built-in route: provider_id is \
              read from the row and bound into nothing",
    },
    DenyPhrase {
        phrase: "tampering still cannot redirect",
        requires_any: &[],
        why: "the custom-origin MAC does not survive a row downgrade — nulling \
              the four custom columns moves the row onto the unauthenticated path",
    },
    DenyPhrase {
        phrase: "cannot redirect your credentials",
        requires_any: &[],
        why: "a provider_id rewrite sends the credential to another shipped provider",
    },
    DenyPhrase {
        phrase: "cannot redirect your traffic",
        requires_any: &[],
        why: "true only while the row stays a custom row, and never for built-in routes",
    },
    DenyPhrase {
        phrase: "redirect a live pass-through credential",
        requires_any: &[],
        why: "state what is scoped: an edited custom origin STOPS the route; a \
              provider_id rewrite MOVES a built-in one",
    },
    DenyPhrase {
        phrase: "integrity-protected against database tampering",
        requires_any: &[],
        why: "the MAC binds an approved destination; it does not protect the \
              route table against a local-database attacker",
    },
    DenyPhrase {
        phrase: "integrity protected against database tampering",
        requires_any: &[],
        why: "the MAC binds an approved destination; it does not protect the \
              route table against a local-database attacker",
    },
    DenyPhrase {
        phrase: "cannot change where a manifest route forwards",
        requires_any: &[],
        why: "a manifest route's destination is chosen by provider_id, which a \
              direct UPDATE can change",
    },
    DenyPhrase {
        phrase: "go anywhere else",
        requires_any: &["gateway"],
        why: "the retired SECURITY.md conclusion; /openai/... can be made to go \
              to any of the shipped provider origins",
    },
];

/// A match is not a claim when it is being retracted or quoted as history.
/// These markers are checked in a tight window around the hit, so a document
/// may say what it used to say while correcting it — which is exactly what
/// `SECURITY.md`, ADR 0019 and the desktop source comment now do.
///
/// This exemption is NOT available to markdown headings: see
/// `new49_sec01_no_heading_claims_that_tampering_cannot_redirect_credentials`.
/// A heading is an assertion by construction and can never be a retraction.
const RETRACTION_MARKERS: &[&str] = &[
    "used to",
    "previously",
    "originally",
    "retired",
    "no longer claim",
    "does not claim",
    "audited string said",
    "not true",
    "was wrong",
    "amended",
    "superseded",
    "this test",
];

/// How far around a hit a retraction marker counts, in normalised bytes.
const RETRACTION_WINDOW: usize = 320;

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .unwrap()
        .parent() // repo root
        .unwrap()
        .to_path_buf()
}

/// Whitespace-normalised, lowercased text plus a map back to byte offsets in
/// the original, so a failure can name a real line number. Every one of the
/// Tier-1 claims was wrapped across lines, so a line-oriented match would have
/// missed most of them.
struct Normalized {
    text: String,
    /// `origin[i]` is the byte offset in the source of the byte at `text[i]`.
    origin: Vec<usize>,
}

fn normalize(src: &str) -> Normalized {
    let mut text = String::with_capacity(src.len());
    let mut origin: Vec<usize> = Vec::with_capacity(src.len());
    let mut pending_space = true; // also trims any leading whitespace
    for (idx, ch) in src.char_indices() {
        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !text.is_empty() {
            text.push(' ');
            while origin.len() < text.len() {
                origin.push(idx);
            }
        }
        pending_space = false;
        for lower in ch.to_lowercase() {
            text.push(lower);
            while origin.len() < text.len() {
                origin.push(idx);
            }
        }
    }
    Normalized { text, origin }
}

/// Byte-offset slice that never splits a UTF-8 character.
fn safe_slice(text: &str, start: usize, end: usize) -> &str {
    let mut lo = start.min(text.len());
    let mut hi = end.min(text.len()).max(lo);
    while lo > 0 && !text.is_char_boundary(lo) {
        lo -= 1;
    }
    while hi < text.len() && !text.is_char_boundary(hi) {
        hi += 1;
    }
    &text[lo..hi]
}

fn line_of(src: &str, byte_offset: usize) -> usize {
    src[..byte_offset.min(src.len())].matches('\n').count() + 1
}

/// Every scannable file in the repository, as `(path relative to root, text)`.
fn inventory(root: &Path) -> Vec<(PathBuf, String)> {
    let audit_root = root.join("docs/activity-onboarding/audit");
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if kind.is_dir() {
                if SKIPPED_DIRS.contains(&name.as_str()) || name == "tests" {
                    continue;
                }
                // Per-audit evidence bundles are frozen history: they quote the
                // false claims because quoting them IS the finding.
                if dir == audit_root {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            if name.contains(".test.") || name.contains(".spec.") {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !SCANNED_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            if entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue; // not UTF-8 text; nothing to claim in it
            };
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            out.push((rel, text));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Deny-list hits in one document, as human-readable report lines.
fn violations(rel: &Path, src: &str) -> Vec<String> {
    let norm = normalize(src);
    let mut hits = Vec::new();
    for deny in DENIED {
        if !deny.requires_any.is_empty()
            && !deny
                .requires_any
                .iter()
                .any(|needle| norm.text.contains(needle))
        {
            continue;
        }
        let mut from = 0usize;
        while let Some(rel_at) = norm.text[from..].find(deny.phrase) {
            let at = from + rel_at;
            from = at + deny.phrase.len();
            let window = safe_slice(
                &norm.text,
                at.saturating_sub(RETRACTION_WINDOW),
                at + deny.phrase.len() + RETRACTION_WINDOW,
            );
            if RETRACTION_MARKERS.iter().any(|m| window.contains(m)) {
                continue; // quoted while being corrected, not asserted
            }
            let line = line_of(src, norm.origin.get(at).copied().unwrap_or(0));
            hits.push(format!(
                "{}:{} — \"{}\"\n      what is true: {}",
                rel.display(),
                line,
                deny.phrase,
                deny.why
            ));
        }
    }
    hits
}

fn guidance() -> &'static str {
    "\n\nNEW-49 / SEC-01. A built-in gateway route selects its destination by an \
     unauthenticated `provider_id`, so an attacker who can write vault.db can \
     repoint a built-in prefix at a DIFFERENT SHIPPED provider's origin with the \
     credential attached, and can null a custom route's four authenticated \
     columns to reach that same path. What IS prevented: no attacker-chosen \
     destination can be injected, and an edited stored custom origin stops the \
     route rather than redirecting it. Say both. The governing text is \
     docs/gateway/SECURITY.md (\"What database tampering can and cannot do to \
     your routes\"), docs/gateway/THREAT_MODEL.md GW-3, and \
     docs/activity-onboarding/SECURITY_AND_PRIVACY.md (\"the local-database \
     attacker\"). If you have just added a real binding, correct those documents \
     and this test in the same commit."
}

// ---------------------------------------------------------------------------
// The assertions
// ---------------------------------------------------------------------------

/// NEW-49 / SEC-01 — no heading anywhere may assert the guarantee.
///
/// Separate from the body scan, and with **no** retraction exemption: the
/// original defect was a section heading, headings are read on their own, and a
/// heading is never a retraction of itself. This is the assertion the mutation
/// control re-introduces the heading to trip.
#[test]
fn new49_sec01_no_heading_claims_that_tampering_cannot_redirect_credentials() {
    const HEADING_CLAIMS: &[&str] = &[
        "tampering cannot redirect",
        "cannot redirect your credentials",
        "cannot redirect your traffic",
        "cannot redirect a credential",
        "redirect a live pass-through credential",
        "cannot be redirected",
    ];
    let root = repo_root();
    let mut offenders = Vec::new();
    for (rel, src) in inventory(&root) {
        if rel.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        for (n, line) in src.lines().enumerate() {
            if !line.trim_start().starts_with('#') {
                continue;
            }
            let heading = normalize(line).text;
            // One report per heading, however many phrases it trips.
            if HEADING_CLAIMS.iter().any(|claim| heading.contains(claim)) {
                offenders.push(format!("{}:{} — {}", rel.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a heading asserts that database tampering cannot redirect credentials, \
         which is the exact claim NEW-49 removed:\n  {}{}",
        offenders.join("\n  "),
        guidance()
    );
}

/// NEW-49 / SEC-01 — no document may re-assert the retired absolute guarantee.
///
/// Whitespace-normalised and case-insensitive, because every one of the
/// original claims was wrapped across lines and a literal grep missed most of
/// them.
#[test]
fn new49_sec01_no_document_asserts_the_retired_absolute_guarantee() {
    let root = repo_root();
    let mut offenders = Vec::new();
    for (rel, src) in inventory(&root) {
        offenders.extend(violations(&rel, &src));
    }
    assert!(
        offenders.is_empty(),
        "{} document(s) claim more tamper resistance than this product has:\n  - {}{}",
        offenders.len(),
        offenders.join("\n  - "),
        guidance()
    );
}

/// NEW-49 / SEC-01 — the correction must still be there.
///
/// Deleting the section is as much a regression as re-asserting the claim: the
/// acceptance of SEC-01 rests on the exclusion being stated in a file the user
/// is pointed at. This fails if someone removes the disclosure instead of
/// maintaining it.
#[test]
fn new49_sec01_the_gateway_security_doc_still_states_the_correction() {
    let root = repo_root();
    let path = root.join("docs/gateway/SECURITY.md");
    let src = fs::read_to_string(&path).expect("docs/gateway/SECURITY.md must exist");
    let text = normalize(&src).text;

    const REQUIRED: &[(&str, &str)] = &[
        (
            "what database tampering can and cannot do to your routes",
            "the section heading that replaced the false one",
        ),
        (
            "provider_id",
            "the unauthenticated selector must be named, not alluded to",
        ),
        (
            "sec-01",
            "the finding id, so a reader can follow it to the audit record",
        ),
        (
            "different shipped provider",
            "what an attacker actually achieves — reassignment among trusted origins",
        ),
        (
            "stops the route rather than redirecting it",
            "what the custom-origin MAC genuinely prevents",
        ),
        (
            "the local-database attacker",
            "the pointer to the full disclosure in SECURITY_AND_PRIVACY.md",
        ),
    ];
    let missing_detail: Vec<String> = REQUIRED
        .iter()
        .filter(|(needle, _)| !text.contains(needle))
        .map(|(needle, why)| format!("\"{needle}\" — {why}"))
        .collect();
    assert!(
        missing_detail.is_empty(),
        "docs/gateway/SECURITY.md no longer states the SEC-01 correction; \
         missing:\n  - {}{}",
        missing_detail.join("\n  - "),
        guidance()
    );

    // And the shape of the disclosure must survive: both halves, still distinct.
    assert!(
        text.contains("no free-form destination can be injected"),
        "docs/gateway/SECURITY.md must still say what IS prevented (free-form \
         destination injection), or the correction reads as a blanket admission \
         and the real protection gets thrown away with the false claim{}",
        guidance()
    );
}

/// Negative control for the scanner itself.
///
/// Runs the real normaliser and the real deny list over the historical
/// sentences and asserts they ARE flagged. Without this, a rotted phrase list
/// or a broken normaliser would make every assertion above pass vacuously.
#[test]
fn new49_sec01_the_scanner_matches_the_historical_claims() {
    // Line-wrapped exactly as it was in docs/gateway/SECURITY.md, to prove the
    // whitespace normalisation is what does the work.
    let historical = "## Why database tampering cannot redirect your credentials\n\n\
         Manifest routes store no origin in the database at all. A same-user\n\
         process editing SQLite cannot make `/openai/...` (with your key\n\
         attached) go anywhere else. The gateway never obeys the bare row.\n";
    let hits = violations(Path::new("synthetic/SECURITY.md"), historical);
    assert!(
        hits.len() >= 2,
        "the scanner failed to flag the historical NEW-49 claim across line \
         breaks — the deny list or the normaliser has rotted, and every other \
         assertion in this file is now vacuous. Hits: {hits:?}"
    );

    let ui_string = "the exact origin must be given here and is\n\
         integrity-protected against database tampering.";
    assert!(
        !violations(Path::new("synthetic/GatewayView.tsx"), ui_string).is_empty(),
        "the scanner failed to flag the retired desktop UI string"
    );

    // ...and it must not flag the corrected wording, or it would force the
    // documents back toward silence instead of accuracy.
    let corrected = "A custom origin is bound into the route's authentication code, so a \
         destination you never approved cannot be injected. An edited stored origin stops the \
         route rather than redirecting it. Built-in routes are not bound the same way.";
    assert!(
        violations(Path::new("synthetic/USER_GUIDE.md"), corrected).is_empty(),
        "the scanner flags the CORRECTED wording; it would push authors toward \
         deleting the disclosure rather than stating it"
    );
}

/// Negative control for the walk.
///
/// The classic failure of a `CARGO_MANIFEST_DIR`-relative scan is a wrong root:
/// it finds nothing and every assertion passes. This pins that the walk really
/// reached the repository and really reached the documents that matter.
#[test]
fn new49_sec01_the_scanner_reads_a_non_empty_inventory() {
    let root = repo_root();
    let files = inventory(&root);
    assert!(
        files.len() > 40,
        "only {} files scanned from {} — the repo root resolution is wrong and \
         the NEW-49 guard is vacuous",
        files.len(),
        root.display()
    );

    for required in [
        "docs/gateway/SECURITY.md",
        "docs/gateway/ARCHITECTURE.md",
        "docs/gateway/THREAT_MODEL.md",
        "docs/gateway/USER_GUIDE.md",
        "THREAT_MODEL.md",
        "crates/gateway/src/routes.rs",
        "apps/desktop/src/components/GatewayView.tsx",
    ] {
        assert!(
            files.iter().any(|(rel, _)| rel == Path::new(required)),
            "{required} was not scanned — the NEW-49 guard does not cover the \
             file the claim lived in"
        );
    }

    // The exclusion must be real and must be narrow: per-audit evidence
    // directories are skipped, the living matrices beside them are not.
    assert!(
        !files
            .iter()
            .any(|(rel, _)| rel
                .starts_with("docs/activity-onboarding/audit/opus-fresh-final-20260729")),
        "a frozen audit evidence bundle was scanned; it quotes the false claims \
         verbatim by design and must never be edited to make a build pass"
    );
    assert!(
        files.iter().any(|(rel, _)| rel
            == Path::new(
                "docs/activity-onboarding/audit/POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md"
            )),
        "the remediation matrices sit directly in docs/activity-onboarding/audit/ \
         and are living documents — they must stay in scope"
    );
}
