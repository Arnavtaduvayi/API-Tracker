//! The `.env` link writer (ADR 0019 D9, TEST_PLAN §10).
//!
//! Linking a project to a route repoints the project's SDK at the local
//! gateway by rewriting its `.env` file(s) through the LOSSLESS document
//! model (`core::envfile`) and the atomic write path (`core::envgov`) — the
//! file is parsed, edited, and re-rendered; comments, ordering, blank lines,
//! quoting, CRLF, and duplicate keys all survive. An environment file is
//! NEVER executed or interpolated.
//!
//! Everything the writer changes is recorded FIRST in
//! `gateway_project_links.prior_env_json` (a versioned JSON document), so
//! unlink and disable restore the exact prior state: a variable that existed
//! before gets its old value back, a variable we created is removed, and a
//! value the USER changed after linking is left alone and reported. There is
//! deliberately no `.env.bak` sibling file: an `.env` holds secrets, and a
//! copy under a name no `.gitignore` covers is a leak primitive — the
//! recorded prior state plus the same-directory atomic temp-file write is
//! the backup story.
//!
//! Scope honesty (SI-16): this module touches ONLY the files the caller
//! explicitly names (or the selected project directory's own `.env`). It
//! never scans the computer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use api_tracker_core::envfile::{EnvDocument, GATEWAY_MARKER_TAG};
use api_tracker_core::envrestore::{RestoreCrypto, SealedValue};
use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::UnlockedVault;
use api_tracker_core::{audit, envgov, providers, scanner};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::routes;
use crate::store;

/// The current `prior_env_json` document version.
/// v1 recorded prior values as PLAINTEXT, gated by a shape predicate.
/// v2 seals every recorded value under the vault's env-restore key
/// (ADR 0028), so secrecy no longer depends on recognising which strings
/// are secret (RA-006). v1 records are still READ — an existing user must
/// still be able to unlink — and are re-sealed or redacted on the next
/// write.
const PRIOR_ENV_VERSION: u32 = 2;

/// Refuse a restore record written by a NEWER build.
///
/// `prior_env_json` records what a file looked like before linking, and a
/// future version may change what the fields mean. Restoring a v2 document
/// under v1 rules could half-restore a file and then delete the record. The
/// version was serialized from the start but never checked; failing closed
/// is the only safe reading of an unknown one.
fn check_prior_env_version(v: u32) -> Result<()> {
    if v > PRIOR_ENV_VERSION {
        return Err(CoreError::Unsupported {
            provider: "gateway".into(),
            capability: "env restore record",
            hint: format!(
                "this project's saved .env restore record is version {v}, but this \
                 build understands up to {PRIOR_ENV_VERSION}. Upgrade Tethra to unlink \
                 this project; the record is left untouched."
            ),
        });
    }
    Ok(())
}

/// What one linked variable looked like before the writer touched it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriorVar {
    pub key: String,
    /// LEGACY (v1 records only): the value before linking, in plaintext.
    ///
    /// Never written by this build. It remains readable so a record made by
    /// an earlier build can still be restored, and so `scrub` can find and
    /// re-seal it. Everything this build records goes in [`Self::sealed`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior: Option<String>,
    /// The value before linking, sealed under the vault's env-restore key.
    ///
    /// `None` when the variable did not exist, or when no key was available
    /// to seal it (see `prior_withheld`) — never because a predicate judged
    /// the value safe to store in the clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<SealedValue>,
    /// The variable existed but its value was NOT recorded, because no
    /// unlocked vault was available to seal it. Restore reports this
    /// honestly instead of silently writing nothing.
    ///
    /// "We could not protect it" and "it is safe to store" must never
    /// resolve to the same behaviour — that equivalence is what RA-006 was.
    #[serde(default)]
    pub prior_withheld: bool,
    /// What the writer wrote, so restore can tell a user edit from its own.
    pub written: String,
    /// Every occurrence's prior value, in file order, when the key appeared
    /// more than once. `EnvDocument::get` is last-wins but `set` rewrites
    /// ALL occurrences, so a single recorded value would restore
    /// `KEY=a` … `KEY=b` as `KEY=b` … `KEY=b`, destroying the first one.
    /// Empty for the ordinary single-occurrence case; additive, so records
    /// written by earlier builds still restore exactly as they did.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prior_all: Vec<String>,
    /// The sealed form of `prior_all`, for the same multi-occurrence case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed_all: Vec<SealedValue>,
}

/// Seal every recorded prior value in `files`, in place.
///
/// This is the single point where a prior value becomes durable, and it is
/// unconditional: no predicate decides whether a value "needs" protecting,
/// because the audited head's predicate classified a Supabase service-role
/// JWT as safe to store in the clear (RA-006).
///
/// Without a key (`crypto` is `None`) the value is **withheld**, not
/// written. Every production path that records a prior value holds an
/// unlocked vault, so this is a genuine can't-happen rather than a routine
/// degradation — but it degrades safely rather than silently.
fn seal_prior_files(
    crypto: Option<&RestoreCrypto>,
    slug: &str,
    mut files: Vec<PriorFile>,
) -> Result<Vec<PriorFile>> {
    for file in &mut files {
        for var in &mut file.vars {
            let plaintext = var.prior.take();
            let plaintext_all = std::mem::take(&mut var.prior_all);
            // Already sealed (a merged record from a previous link).
            if var.sealed.is_some() || !var.sealed_all.is_empty() {
                continue;
            }
            let Some(crypto) = crypto else {
                if plaintext.is_some() {
                    var.prior_withheld = true;
                }
                continue;
            };
            if let Some(value) = plaintext {
                var.sealed = Some(crypto.seal(slug, &file.path, &var.key, &value)?);
            }
            for value in plaintext_all {
                var.sealed_all
                    .push(crypto.seal(slug, &file.path, &var.key, &value)?);
            }
        }
    }
    Ok(files)
}

/// Open a stored record into the in-memory plaintext shape `restore_file`
/// consumes.
///
/// The plaintext exists only for the duration of the restore and is never
/// written back to the database. A v1 (legacy) record already carries
/// plaintext and is passed through unchanged, so an existing user can still
/// unlink after upgrading.
///
/// Without a key, a sealed value is reported as **withheld** rather than
/// treated as absent: `restore_file` deletes the line when it believes no
/// prior value existed, and deleting a line whose value we merely could not
/// read would destroy the user's configuration.
fn open_prior_file(
    crypto: Option<&RestoreCrypto>,
    slug: &str,
    file: &PriorFile,
) -> Result<PriorFile> {
    let mut out = file.clone();
    for var in &mut out.vars {
        if var.sealed.is_none() && var.sealed_all.is_empty() {
            continue; // v1 record: `prior` / `prior_all` already hold it
        }
        let Some(crypto) = crypto else {
            var.prior = None;
            var.prior_all.clear();
            var.prior_withheld = true;
            continue;
        };
        if let Some(sealed) = &var.sealed {
            let opened = crypto.open(slug, &file.path, &var.key, sealed)?;
            var.prior = Some(opened.expose().to_string());
        }
        var.prior_all = var
            .sealed_all
            .iter()
            .map(|sealed| {
                crypto
                    .open(slug, &file.path, &var.key, sealed)
                    .map(|v| v.expose().to_string())
            })
            .collect::<Result<Vec<_>>>()?;
    }
    Ok(out)
}

/// Whether a prior `.env` value is safe to record in the plaintext
/// `prior_env_json` column.
///
/// Deliberately a strict allowlist rather than a secret-detector: the column
/// is plaintext and the cost of being wrong is a stored credential, while the
/// cost of being conservative is one line the user restores by hand. A value
/// qualifies only if it is an `http`/`https` URL that carries no userinfo, no
/// query string, no fragment, and no key-material-shaped path segment — or a
/// proxy-list-shaped value (comma-separated hosts/IPs/suffixes).
///
/// The rule about everything AFTER the authority is not theoretical. This
/// allowlist originally inspected only the authority and waved through
/// whatever followed it, so
/// `OPENAI_BASE_URL=https://api.example.com/v1?api_key=sk-…` was written
/// verbatim into `vault.db` and an audit recovered the planted key from the
/// raw file. Nothing can tell `?version=2` from `?api_key=…`, so a query
/// string is never persisted at all, and restore degrades HONESTLY instead of
/// silently: the value is marked `prior_withheld`, the user sees
/// [`LinkWarning::PriorValueWithheld`] BEFORE they confirm the link, and
/// unlink leaves the line in place and reports
/// [`RestoreOutcome::PriorNotRecorded`] rather than guessing at a value it
/// never kept.
pub fn prior_value_is_recordable(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    if let Some(rest) = v
        .strip_prefix("http://")
        .or_else(|| v.strip_prefix("https://"))
    {
        // Sever the authority from the rest BEFORE judging either: the old
        // rule stopped here and never looked at what followed.
        let (authority, tail) = match rest.find(['/', '?', '#']) {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        // `user:pass@host` in a base URL is a credential.
        if authority.contains('@') {
            return false;
        }
        if tail.contains('?') || tail.contains('#') {
            return false;
        }
        // A path segment can BE the credential — a Slack-style webhook URL
        // keeps its secret in the last one — so each has to look ordinary.
        return tail
            .split('/')
            .all(|segment| !scanner::looks_like_key_material(segment));
    }
    // A NO_PROXY-style list: hosts, IPs, dotted suffixes, optional ports.
    // Every part must LOOK like a host — dotted, bracketed IPv6, or one of
    // the bare loopback names. A bare token of allowed characters is not
    // enough: `sk-proj-...` is exactly that shape.
    v.split(',').all(|part| {
        let p = part.trim().trim_start_matches('.');
        if p.is_empty() || p.len() > 255 {
            return false;
        }
        if !p
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']' | '*'))
        {
            return false;
        }
        p.eq_ignore_ascii_case("localhost")
            || p.starts_with('[')
            || p.contains('.')
            || p.contains(':')
    })
}

/// Everything the writer changed in one file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriorFile {
    pub path: String,
    /// Whether the file existed before linking (a created file is deleted on
    /// restore only if nothing else was added to it).
    pub existed: bool,
    pub vars: Vec<PriorVar>,
}

/// The versioned `prior_env_json` document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriorEnv {
    pub v: u32,
    pub port: u16,
    pub files: Vec<PriorFile>,
}

/// A non-fatal caution the user should see before confirming a link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkWarning {
    /// The file is tracked by git: the loopback URL (with its 128-bit link
    /// slug) would be committed and shared.
    GitTracked { path: String },
    /// The file has git history even if currently untracked.
    GitHistory { path: String },
    /// The file looks like a template (`.env.example` etc.) — templates are
    /// shared; gateway wiring is machine-local.
    TemplateFile { path: String },
    /// The file sits under a CI/shared-configuration directory.
    SharedConfiguration { path: String },
    /// The file is outside the selected project directory.
    OutsideProject { path: String },
    /// The file is read-only; the atomic rename may still replace it.
    ReadOnly { path: String },
    /// `HTTP_PROXY`/`HTTPS_PROXY` is set in this file: without the written
    /// `NO_PROXY` entry, SDK traffic to 127.0.0.1 could detour through the
    /// proxy in cleartext (THREAT_MODEL GW-12).
    ProxyVariablePresent { path: String, key: String },
    /// The variable already had a value; it is recorded and will be restored
    /// on unlink.
    ExistingValueRecorded { path: String, key: String },
    /// The variable already had a value that does NOT look like a base URL
    /// or proxy list — so it is not recorded in the plaintext restore record
    /// and cannot be restored automatically. Write it down before linking.
    PriorValueWithheld { path: String, key: String },
    /// The file has duplicate definitions of a written key; every occurrence
    /// is repointed (dotenv loaders read the last one).
    DuplicateKey { path: String, key: String },
    /// The file has unparseable lines (preserved verbatim, never touched).
    MalformedLines { path: String, count: usize },
    /// docker-compose.yml exists next to the project: compose services read
    /// environment from the compose file, not this `.env`, unless wired.
    DockerComposePresent { path: String },
    /// The project declares dependencies but none look like a dotenv loader;
    /// the SDK may not read `.env` at all (coverage honesty, GW-13).
    NoDotenvLoaderDetected { path: String },
}

/// The planned rewrite of one file.
#[derive(Debug, Clone, Serialize)]
pub struct FilePlan {
    pub path: String,
    /// Whether the file exists yet (a missing default `.env` is created).
    pub exists: bool,
    /// Whether applying would change the file at all.
    pub changed: bool,
    /// The proposed rendered content. Held as [`SecretString`]-adjacent data
    /// only transiently in memory; serialized plans carry the DIFF, not the
    /// content.
    #[serde(skip)]
    pub new_content: String,
    #[serde(skip)]
    pub old_content: String,
    /// Masked diff, with the gateway-owned lines shown verbatim (D9: the
    /// user approves the exact base URL).
    pub diff: String,
    pub warnings: Vec<LinkWarning>,
    /// What restore will need to know, captured at plan time.
    #[serde(skip)]
    pub prior: PriorFile,
}

/// A complete, previewable link plan. `digest` binds BOTH sides of the
/// preview — the content each file had when the diff was rendered and the
/// content it would be rewritten to — so apply re-plans and refuses if
/// anything changed underneath the preview.
#[derive(Debug, Clone, Serialize)]
pub struct LinkPlan {
    pub project_id: String,
    pub project_name: String,
    pub route_prefix: String,
    pub provider_id: String,
    pub link_slug: String,
    /// Whether the slug comes from an existing link row (re-link) or was
    /// freshly generated for this plan.
    pub existing_link: bool,
    pub port: u16,
    /// The exact base URL every written variable points at.
    pub base_url: String,
    /// The variables that will be written.
    pub vars: Vec<String>,
    pub files: Vec<FilePlan>,
    pub warnings: Vec<LinkWarning>,
    /// BLAKE3 over every file's previewed INPUT and planned output, hex.
    /// Binds preview to apply; see [`plan_digest`].
    pub digest: String,
}

/// Bind a plan to the exact state it was computed against.
///
/// The digest covers, for every file, the content the preview READ as well as
/// the content it would WRITE. Hashing only the output made the documented
/// promise ("refuses when any file changed since the preview") false wherever
/// the rewrite is not injective — and it is not: the writer sets the same
/// gateway URL whatever the variable held before, so a user who edited
/// `OPENAI_BASE_URL` between preview and apply produced a byte-identical
/// planned output, matched the digest, and had the edit overwritten without
/// ever seeing it in a diff (ZFT-023). Binding the input makes the refusal
/// mean what it says.
///
/// Fields are length-prefixed so no two different plans can serialize to the
/// same byte stream (`("a", "bc")` must not hash like `("ab", "c")`).
fn plan_digest(slug: &str, files: &[FilePlan]) -> String {
    fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    let mut hasher = blake3::Hasher::new();
    field(&mut hasher, slug.as_bytes());
    for p in files {
        field(&mut hasher, p.path.as_bytes());
        field(&mut hasher, p.old_content.as_bytes());
        field(&mut hasher, p.new_content.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// What to link. `files` empty means "the selected directory's own `.env`".
#[derive(Debug, Clone)]
pub struct LinkRequest {
    pub project_id: String,
    pub project_name: String,
    pub route_prefix: String,
    pub project_dir: Option<PathBuf>,
    pub files: Vec<PathBuf>,
    /// Write this variable name instead of the provider's declared ones
    /// (required for providers that declare none).
    pub var_override: Option<String>,
}

/// The marker comment placed above every line the writer owns
/// (PRODUCT_BEHAVIOR step 3 wording).
pub fn marker_comment(provider_id: &str, project_name: &str) -> String {
    format!(
        "{GATEWAY_MARKER_TAG} route: {provider_id} (project: {project_name}) — remove this \
         line if 127.0.0.1 refuses connections, or run: tethra gateway status"
    )
}

/// The `NO_PROXY` entries the gateway needs so SDK traffic to 127.0.0.1
/// never detours through a corporate proxy in cleartext (GW-12).
const NO_PROXY_ENTRIES: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

fn err(msg: String) -> CoreError {
    CoreError::InvalidInput(msg)
}

/// Which env-var names to write for a provider, honoring an override.
fn link_vars(provider_id: &str, var_override: Option<&str>) -> Result<Vec<String>> {
    if let Some(var) = var_override {
        let var = var.trim();
        if var.is_empty() || var.contains('=') || var.contains(char::is_whitespace) {
            return Err(err(format!("'{var}' is not a variable name")));
        }
        return Ok(vec![var.to_string()]);
    }
    let declared = providers::find(provider_id)
        .and_then(|m| m.gateway.as_ref())
        .map(|g| g.env_vars.clone())
        .unwrap_or_default();
    if declared.is_empty() {
        return Err(CoreError::Unsupported {
            provider: provider_id.to_string(),
            capability: "gateway_env_link",
            hint: "this provider declares no base-URL environment variable; pass the \
                   variable name explicitly (--var NAME) if its SDK supports one"
                .into(),
        });
    }
    Ok(declared)
}

/// The client-side base path for a provider ("" when undeclared).
fn base_path(provider_id: &str) -> String {
    providers::find(provider_id)
        .and_then(|m| m.gateway.as_ref())
        .map(|g| g.base_path.clone())
        .unwrap_or_default()
}

/// Compute the plan. Read-only: touches no file, writes no row.
pub fn plan_link(conn: &Connection, req: &LinkRequest) -> Result<LinkPlan> {
    let Some((provider_id, _custom)) = route_provider(conn, &req.route_prefix)? else {
        return Err(CoreError::NotFound {
            kind: "gateway route",
            ident: req.route_prefix.clone(),
        });
    };
    plan_link_as_provider(conn, req, &provider_id, None)
}

/// Compute the plan for a named provider whose route row may not exist yet.
///
/// The tracking orchestrator (ADR 0022) shows one combined review screen —
/// including the exact `.env` diff — BEFORE it creates any route row, so the
/// provider cannot be resolved from `gateway_routes` at that point. This is
/// the same read-only computation as [`plan_link`] minus the route lookup;
/// nothing that validates origins, digests, or writes is bypassed
/// (`apply_link` still re-plans through the route row and still refuses on
/// digest mismatch). `port_override` exists solely for dry-run previews on a
/// vault with no persisted port yet: a plan built on an override is for
/// display only and can never apply cleanly unless that port is persisted
/// first, because `apply_link`'s re-plan reads the persisted port.
pub fn plan_link_as_provider(
    conn: &Connection,
    req: &LinkRequest,
    provider_id: &str,
    port_override: Option<u16>,
) -> Result<LinkPlan> {
    plan_link_as_provider_projected(conn, req, provider_id, port_override, &BTreeMap::new())
}

/// Like [`plan_link_as_provider`], planning over PROJECTED file contents:
/// entries in `projected` (path string → content) are treated as each
/// file's current content instead of reading disk. This is how the
/// tracking orchestrator builds one combined multi-provider diff whose
/// digests stay honest — provider N's plan is computed over provider
/// N−1's planned output, and apply (in the same order) re-plans against a
/// disk state that matches exactly. Any EXTERNAL mutation between preview
/// and apply still fails the digest check as before.
pub fn plan_link_as_provider_projected(
    conn: &Connection,
    req: &LinkRequest,
    provider_id: &str,
    port_override: Option<u16>,
    projected: &BTreeMap<String, String>,
) -> Result<LinkPlan> {
    let provider_id = provider_id.to_string();
    let vars = link_vars(&provider_id, req.var_override.as_deref())?;

    let config = store::load_config(conn)?;
    let Some(port) = port_override.or(config.port) else {
        return Err(err(
            "the gateway has no persisted port yet, so a stable base URL cannot be \
             written. Enable the gateway (or run `tethra gateway serve` once) first."
                .into(),
        ));
    };

    let existing = routes::find_project_link(conn, &req.project_id, &req.route_prefix)?;
    let (link_slug, existing_link) = match &existing {
        Some(row) => (row.link_slug.clone(), true),
        None => (routes::new_link_slug(), false),
    };
    let base_url = format!(
        "http://127.0.0.1:{port}/p/{link_slug}/{}{}",
        req.route_prefix,
        base_path(&provider_id)
    );

    let files = resolve_files(req)?;
    let marker = marker_comment(&provider_id, &req.project_name);
    let mut plans = Vec::new();
    let mut all_warnings = Vec::new();
    for path in &files {
        let base = projected
            .get(&path.display().to_string())
            .map(String::as_str);
        let plan = plan_file(path, req, &vars, &base_url, &marker, port, base)?;
        all_warnings.extend(plan.warnings.clone());
        plans.push(plan);
    }
    project_level_warnings(req, &mut all_warnings);

    let digest = plan_digest(&link_slug, &plans);
    Ok(LinkPlan {
        project_id: req.project_id.clone(),
        project_name: req.project_name.clone(),
        route_prefix: req.route_prefix.clone(),
        provider_id,
        link_slug,
        existing_link,
        port,
        base_url,
        vars,
        files: plans,
        warnings: all_warnings,
        digest,
    })
}

/// Apply a previously previewed plan. Re-plans internally and refuses when
/// any file changed since the preview (`digest` mismatch), so what the user
/// confirmed is exactly what is written. "Changed" means changed at all: the
/// digest binds the previewed INPUT as well as the planned output, so an edit
/// the rewrite would have flattened back to the same result still refuses
/// (ZFT-023).
pub fn apply_link(
    conn: &Connection,
    crypto: Option<&RestoreCrypto>,
    req: &LinkRequest,
    approved: &LinkPlan,
) -> Result<PriorEnv> {
    let mut replanned = plan_link_with_slug(conn, req, &approved.link_slug)?;
    if replanned.digest != approved.digest {
        return Err(err(
            "the environment files changed since the preview; re-run the link to see \
             the current diff"
                .into(),
        ));
    }

    // The link row and its restore record are committed BEFORE the files are
    // touched: if the process dies between the two, the recorded prior state
    // describes at worst MORE restoration than needed (restoring a value
    // that was never overwritten is a no-op), never less.
    if !replanned.existing_link {
        routes::add_project_link_with_slug(
            conn,
            &req.project_id,
            &req.route_prefix,
            &replanned.link_slug,
        )?;
    }
    // Seal BEFORE merging, so nothing that reaches `prior_json` has ever
    // held a plaintext value (RA-006).
    let fresh = seal_prior_files(
        crypto,
        &replanned.link_slug,
        replanned.files.iter().map(|f| f.prior.clone()).collect(),
    )?;
    let prior = PriorEnv {
        v: PRIOR_ENV_VERSION,
        port: replanned.port,
        files: merge_prior(existing_prior(conn, crypto, &replanned.link_slug)?, fresh),
    };
    let prior_json = serde_json::to_string(&prior).map_err(CoreError::Serde)?;
    let primary = replanned.files.first().map(|f| f.path.clone());
    routes::update_link_env(
        conn,
        &replanned.link_slug,
        primary.as_deref(),
        Some(&prior_json),
    )?;

    for file in &mut replanned.files {
        if !file.changed {
            continue;
        }
        if file.exists {
            envgov::atomic_write(Path::new(&file.path), &file.new_content)?;
        } else {
            envgov::write_new(Path::new(&file.path), &file.new_content)?;
        }
        // An `atomic_write` that dies between write and rename leaves a temp
        // file holding the COMPLETE new `.env`, credential values included.
        // Only the export cleanup ever swept for those, and it sweeps
        // directories read from `env_exports` — a table this path never
        // writes, so a link's orphan was never collected by anything
        // (`NEW-29`). Best-effort: a failed sweep must not fail a link that
        // succeeded.
        if let Some(dir) = Path::new(&file.path).parent() {
            envgov::sweep_orphaned_temp_files_in(dir);
        }
    }
    audit::record(
        conn,
        "gateway_env_linked",
        Some(&req.project_id),
        None,
        &format!(
            "prefix={} files={}",
            req.route_prefix,
            replanned.files.len()
        ),
    )?;
    Ok(prior)
}

/// Plan with a FIXED slug (apply-time re-plan; also desktop's plan→apply).
pub fn plan_link_with_slug(conn: &Connection, req: &LinkRequest, slug: &str) -> Result<LinkPlan> {
    let mut plan = plan_link(conn, req)?;
    if plan.link_slug != slug {
        // Recompute with the caller's slug (plan_link generated a fresh one).
        let Some((provider_id, _)) = route_provider(conn, &req.route_prefix)? else {
            return Err(CoreError::NotFound {
                kind: "gateway route",
                ident: req.route_prefix.clone(),
            });
        };
        let base_url = format!(
            "http://127.0.0.1:{}/p/{slug}/{}{}",
            plan.port,
            req.route_prefix,
            base_path(&provider_id)
        );
        let marker = marker_comment(&provider_id, &req.project_name);
        let files = resolve_files(req)?;
        let mut plans = Vec::new();
        let mut warnings = Vec::new();
        for path in &files {
            let fp = plan_file(path, req, &plan.vars, &base_url, &marker, plan.port, None)?;
            warnings.extend(fp.warnings.clone());
            plans.push(fp);
        }
        project_level_warnings(req, &mut warnings);
        plan.digest = plan_digest(slug, &plans);
        plan.link_slug = slug.to_string();
        plan.base_url = base_url;
        plan.files = plans;
        plan.warnings = warnings;
    }
    Ok(plan)
}

/// Which files a request names: explicit list, or the project dir's `.env`.
fn resolve_files(req: &LinkRequest) -> Result<Vec<PathBuf>> {
    if !req.files.is_empty() {
        for f in &req.files {
            if f.is_dir() {
                return Err(err(format!(
                    "{} is a directory; pass the environment FILE to link",
                    f.display()
                )));
            }
        }
        return Ok(req.files.clone());
    }
    let Some(dir) = &req.project_dir else {
        return Err(err(
            "no environment file selected: pass --env-file <path>, or --dir <project \
             directory> to use its .env"
                .into(),
        ));
    };
    if !dir.is_dir() {
        return Err(err(format!("{} is not a directory", dir.display())));
    }
    Ok(vec![dir.join(".env")])
}

/// Plan the rewrite of one file, collecting warnings. `projected`, when
/// set, is used as the file's current content (the multi-provider
/// combined-plan case); disk is read otherwise.
#[allow(clippy::too_many_arguments)]
fn plan_file(
    path: &Path,
    req: &LinkRequest,
    vars: &[String],
    base_url: &str,
    marker: &str,
    _port: u16,
    projected: Option<&str>,
) -> Result<FilePlan> {
    // Symlink policy: refuse. An atomic rename would silently REPLACE the
    // symlink with a regular file, disconnecting whatever the link pointed
    // at — surprising in exactly the wrong way for a shared dotfile setup.
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(err(format!(
            "{} is a symlink; refusing to rewrite it (link the target file directly)",
            path.display()
        )));
    }

    let (exists, old_content) = match projected {
        // A projected file exists by the time this plan applies (the
        // preceding provider's apply wrote it).
        Some(content) => (true, content.to_string()),
        None => {
            let exists = path.exists();
            let content = if exists {
                std::fs::read_to_string(path).map_err(CoreError::Io)?
            } else {
                String::new()
            };
            (exists, content)
        }
    };
    let mut doc = EnvDocument::parse(&old_content);
    let path_str = path.display().to_string();
    let mut warnings = Vec::new();

    file_warnings(path, &path_str, req, exists, &doc, &mut warnings);

    let mut prior_vars = Vec::new();
    for var in vars {
        let existing = doc.get(var).map(|e| e.value.expose().to_string());
        // EVERY prior value is recorded, and every recorded value is sealed
        // before it is persisted (`seal_prior_files`). The audited head
        // decided here, with a shape predicate, and the predicate was wrong
        // about real key material (RA-006) — so there is no longer a
        // decision to get wrong. What lands in `prior_env_json` is
        // ciphertext regardless of what the value looks like.
        if let Some(prior) = &existing {
            if prior != base_url {
                warnings.push(LinkWarning::ExistingValueRecorded {
                    path: path_str.clone(),
                    key: var.clone(),
                });
            }
        }
        let all: Vec<String> = doc
            .entries()
            .filter(|e| &e.key == var)
            .map(|e| e.value.expose().to_string())
            .collect();
        if all.len() > 1 {
            warnings.push(LinkWarning::DuplicateKey {
                path: path_str.clone(),
                key: var.clone(),
            });
        }
        let prior_all = if all.len() > 1 { all } else { Vec::new() };
        prior_vars.push(PriorVar {
            key: var.clone(),
            prior_withheld: false,
            prior: existing,
            sealed: None,
            prior_all,
            sealed_all: Vec::new(),
            written: base_url.to_string(),
        });
        doc.set_with_comment(var, SecretString::new(base_url.to_string()), marker);
    }

    // NO_PROXY: extend every existing spelling, or create `NO_PROXY`.
    let proxy_keys: Vec<String> = doc
        .entries()
        .filter(|e| e.key.eq_ignore_ascii_case("no_proxy"))
        .map(|e| e.key.clone())
        .collect();
    if proxy_keys.is_empty() {
        prior_vars.push(PriorVar {
            key: "NO_PROXY".into(),
            prior: None,
            sealed: None,
            prior_withheld: false,
            prior_all: Vec::new(),
            sealed_all: Vec::new(),
            written: NO_PROXY_ENTRIES.join(","),
        });
        doc.set_with_comment(
            "NO_PROXY",
            SecretString::new(NO_PROXY_ENTRIES.join(",")),
            marker,
        );
    } else {
        for key in proxy_keys {
            let current = doc
                .get(&key)
                .map(|e| e.value.expose().to_string())
                .unwrap_or_default();
            let extended = extend_no_proxy(&current);
            if extended != current {
                // A NO_PROXY list is SHAPED like non-secret configuration,
                // but nothing stops a user keeping something else under that
                // name — which is why this value is sealed like every other
                // one rather than judged by its shape.
                prior_vars.push(PriorVar {
                    key: key.clone(),
                    prior: Some(current.clone()),
                    sealed: None,
                    prior_withheld: false,
                    prior_all: Vec::new(),
                    sealed_all: Vec::new(),
                    written: extended.clone(),
                });
                doc.set(&key, SecretString::new(extended));
            }
        }
    }

    let new_content = doc.render();
    let changed = new_content != old_content;
    let unmasked: Vec<&str> = vars
        .iter()
        .map(|s| s.as_str())
        .chain(["NO_PROXY", "no_proxy"])
        .collect();
    let diff = envgov::render_diff_with_unmasked(&path_str, &old_content, &new_content, &unmasked);
    Ok(FilePlan {
        path: path_str.clone(),
        exists,
        changed,
        new_content,
        old_content,
        diff,
        warnings,
        prior: PriorFile {
            path: path_str,
            existed: exists,
            vars: prior_vars,
        },
    })
}

/// Append the loopback entries missing from a NO_PROXY list.
fn extend_no_proxy(current: &str) -> String {
    let have: Vec<&str> = current
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let mut out = current.trim().to_string();
    for needed in NO_PROXY_ENTRIES {
        if !have.iter().any(|h| h.eq_ignore_ascii_case(needed)) {
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(needed);
        }
    }
    out
}

/// Per-file cautions: git status, template class, CI paths, scope, proxy
/// variables, malformed lines, read-only.
fn file_warnings(
    path: &Path,
    path_str: &str,
    req: &LinkRequest,
    exists: bool,
    doc: &EnvDocument,
    warnings: &mut Vec<LinkWarning>,
) {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if matches!(
        envgov::classify_file_name(&file_name),
        Some(envgov::EnvFileClass::Template)
    ) {
        warnings.push(LinkWarning::TemplateFile {
            path: path_str.to_string(),
        });
    }
    if path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some(".github") | Some(".gitlab") | Some(".circleci") | Some("ci")
        )
    }) {
        warnings.push(LinkWarning::SharedConfiguration {
            path: path_str.to_string(),
        });
    }
    if let Some(dir) = &req.project_dir {
        let canonical_dir = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        let canonical_file = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if !canonical_file.starts_with(&canonical_dir) {
            warnings.push(LinkWarning::OutsideProject {
                path: path_str.to_string(),
            });
        }
    }
    if exists {
        if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
            match envgov::gitignore_protects(parent, &name.to_string_lossy()) {
                envgov::GitStatus::Tracked => warnings.push(LinkWarning::GitTracked {
                    path: path_str.to_string(),
                }),
                envgov::GitStatus::Untracked => {
                    // History survives untracking; envgov::discover reports it
                    // through EnvFileInfo, but here a cheap approximation is
                    // enough: only Tracked is a hard warning, history is
                    // covered by discover-time governance.
                }
                _ => {}
            }
        }
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().readonly() {
                warnings.push(LinkWarning::ReadOnly {
                    path: path_str.to_string(),
                });
            }
        }
        let malformed = doc
            .problems()
            .iter()
            .filter(|p| matches!(p.kind, api_tracker_core::envfile::EnvProblemKind::Malformed))
            .count();
        if malformed > 0 {
            warnings.push(LinkWarning::MalformedLines {
                path: path_str.to_string(),
                count: malformed,
            });
        }
        for e in doc.entries() {
            let upper = e.key.to_ascii_uppercase();
            if (upper == "HTTP_PROXY" || upper == "HTTPS_PROXY" || upper == "ALL_PROXY")
                && !e.value.expose().trim().is_empty()
            {
                warnings.push(LinkWarning::ProxyVariablePresent {
                    path: path_str.to_string(),
                    key: e.key.clone(),
                });
            }
        }
    }
}

/// Project-directory-level heuristics (compose file, dotenv loader).
fn project_level_warnings(req: &LinkRequest, warnings: &mut Vec<LinkWarning>) {
    let Some(dir) = &req.project_dir else {
        return;
    };
    for compose in ["docker-compose.yml", "docker-compose.yaml", "compose.yaml"] {
        let p = dir.join(compose);
        if p.exists() {
            warnings.push(LinkWarning::DockerComposePresent {
                path: p.display().to_string(),
            });
            break;
        }
    }
    // Cheap loader heuristic: a Node project whose package.json never
    // mentions dotenv probably does not read .env at runtime. Reported as
    // information, not a blocker — many SDKs read the variable directly
    // from the environment instead.
    let pkg = dir.join("package.json");
    if let Ok(text) = std::fs::read_to_string(&pkg) {
        if !text.contains("dotenv") {
            warnings.push(LinkWarning::NoDotenvLoaderDetected {
                path: pkg.display().to_string(),
            });
        }
    }
}

/// The provider behind a route prefix, from the routes table.
pub fn route_provider(conn: &Connection, prefix: &str) -> Result<Option<(String, bool)>> {
    Ok(conn
        .query_row(
            "SELECT provider_id, custom_origin IS NOT NULL FROM gateway_routes
             WHERE route_prefix = ?1",
            params![prefix],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
        )
        .optional()?)
}

fn existing_prior(
    conn: &Connection,
    crypto: Option<&RestoreCrypto>,
    slug: &str,
) -> Result<Vec<PriorFile>> {
    let row: Option<Option<String>> = conn
        .query_row(
            "SELECT prior_env_json FROM gateway_project_links WHERE link_slug = ?1",
            params![slug],
            |r| r.get(0),
        )
        .optional()?;
    let Some(Some(json)) = row else {
        return Ok(Vec::new());
    };
    let mut parsed: PriorEnv = serde_json::from_str(&json).map_err(CoreError::Serde)?;
    check_prior_env_version(parsed.v)?;
    // A v1 record holds PLAINTEXT values. `merge_prior` keeps the FIRST
    // recorded prior, so without this every re-link would copy that value
    // straight back into the column (ZFT-016). Re-seal it instead, so an
    // upgraded user's restore record survives AND stops being plaintext;
    // with no key available, redact rather than carry it forward.
    if crypto.is_some() {
        parsed.files = seal_prior_files(crypto, slug, parsed.files)?;
    } else {
        redact_all_plaintext(&mut parsed);
    }
    Ok(parsed.files)
}

/// Drop every PLAINTEXT prior value, marking each one withheld.
///
/// Used when no key is available to re-seal a legacy v1 record: carrying the
/// plaintext forward into a fresh write would re-commit exactly the leak
/// RA-006 identified, and a withheld value is reported honestly rather than
/// silently dropped. Returns whether anything changed.
fn redact_all_plaintext(prior: &mut PriorEnv) -> bool {
    let mut changed = false;
    for file in &mut prior.files {
        for var in &mut file.vars {
            if var.prior.is_some() || !var.prior_all.is_empty() {
                var.prior = None;
                var.prior_all.clear();
                var.prior_withheld = true;
                changed = true;
            }
            if !var.prior_all.is_empty()
                && !var.prior_all.iter().all(|v| prior_value_is_recordable(v))
            {
                // Per-occurrence restore is all-or-nothing: keeping the
                // recordable half would restore `KEY=a` … `KEY=b` wrongly.
                var.prior_all.clear();
                var.prior = None;
                var.prior_withheld = true;
                changed = true;
            }
        }
    }
    changed
}

/// Re-filter every stored restore record against the current recordability
/// rule, in place.
///
/// Fixing [`prior_value_is_recordable`] stops NEW leaks; rows a previous build
/// wrote still hold the value the audit recovered from `vault.db` (ZFT-016),
/// and nothing else ever rewrites them. This is the migration for those rows:
/// each affected variable loses its recorded value and gains `prior_withheld`,
/// so unlink reports [`RestoreOutcome::PriorNotRecorded`] instead of quietly
/// claiming a restore it can no longer perform.
///
/// Rows written by a NEWER build are left untouched — this build cannot know
/// what their fields mean, and a half-understood rewrite is worse than a
/// value it will refuse to read anyway.
///
/// Returns the number of link rows rewritten. Idempotent.
/// Run [`scrub_stored_prior_env`] once per vault, guarded by a marker in
/// `vault_meta`.
///
/// The scrub is a ONE-TIME data migration for rows written by builds that
/// recorded query strings and secret-shaped path segments in plaintext
/// (`ZFT-016`). It cannot live in `core::db::migrate` — the filtering logic
/// is Rust in this crate, and `core` must not depend on the gateway — so
/// it runs from the application entry points instead, and the marker keeps
/// it from re-scanning every link row on every command.
///
/// Best-effort by design: a vault that cannot be scrubbed (read-only, a
/// concurrent writer) must not stop the command the user actually asked
/// for. The lazy path in `existing_prior` still redacts any row this misses
/// the next time that link is touched.
pub fn scrub_stored_prior_env_once(
    conn: &Connection,
    crypto: Option<&RestoreCrypto>,
) -> Result<usize> {
    let done: Option<String> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = ?1",
            [SCRUB_MARKER],
            |r| r.get(0),
        )
        .optional()?;
    if done.is_some() {
        return Ok(0);
    }
    // With no key this would REDACT legacy plaintext rather than re-seal it,
    // destroying the user's ability to undo a link made by an earlier build.
    // Losing undo is not an acceptable price for a scrub that a later,
    // unlocked call can do properly, so the marker is left unset and the
    // work is deferred until a caller can actually re-seal.
    if crypto.is_none() {
        return Ok(0);
    }

    // ONE TRANSACTION over the rewrite AND the marker (`ENC-01`).
    //
    // Without it the loop committed each row on its own and the marker was a
    // separate statement afterwards, so an interruption could leave the vault
    // half-migrated with nothing recording that. Half-migrated is not itself
    // dangerous here — the rewrite is idempotent and the lazy path in
    // `existing_prior` still redacts whatever a pass missed — but "the marker
    // says done" and "every row is sealed" have to be the same fact, or a
    // resumed run will skip the remainder.
    //
    // BEGIN IMMEDIATE rather than DEFERRED: this is a read-modify-write over
    // rows the desktop, the CLI and the gateway all touch, and taking the
    // write lock up front turns a lost update into an honest `Busy`.
    //
    // No plaintext is deleted before its sealed replacement is committed:
    // every row is rewritten in place with the sealed form, and the old bytes
    // are only released when this transaction commits.
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let outcome = (|| -> Result<usize> {
        let scrubbed = scrub_stored_prior_env(conn, crypto)?;
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![SCRUB_MARKER, api_tracker_core::clock::now_rfc3339()],
        )?;
        // A version alongside the timestamp, so a future build can tell "this
        // vault was migrated by the v1 rule" from "never migrated" without
        // re-scanning every link row.
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![SCRUB_VERSION_KEY, PRIOR_ENV_VERSION.to_string()],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![SCRUB_COUNT_KEY, scrubbed.to_string()],
        )?;
        Ok(scrubbed)
    })();
    match outcome {
        Ok(scrubbed) => {
            conn.execute_batch("COMMIT")?;
            // The rows are sealed, but the pages holding their plaintext can
            // still sit in the write-ahead log. `secure_delete` (set in
            // `db::configure`) overwrites freed pages inside the database
            // file; the WAL is a separate file and needs the checkpoint.
            // Documented honestly in KNOWN_LIMITATIONS.md: this reduces
            // residue, it does not overwrite free space elsewhere on the
            // volume, and it cannot reach a filesystem snapshot or a backup
            // taken before the upgrade.
            api_tracker_core::db::checkpoint_truncate(conn);
            Ok(scrubbed)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// `vault_meta` keys recording that the legacy-rollback migration ran, what
/// rule it applied, and how much it rewrote. Values are counts and
/// timestamps; no key material and no restore value is ever recorded here.
const SCRUB_MARKER: &str = "envlink_prior_scrub_v1";
const SCRUB_VERSION_KEY: &str = "envlink_prior_scrub_version";
const SCRUB_COUNT_KEY: &str = "envlink_prior_scrub_rows";

/// What one legacy-rollback migration pass did. Carries counts and a status —
/// never a value, and never a reason a value could be reconstructed from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreUpgrade {
    /// The migration ran to completion in this call.
    pub ran: bool,
    /// Link rows re-sealed. Zero is normal: most vaults have no legacy rows.
    pub rewritten: usize,
    /// A previous run already completed it; nothing was scanned.
    pub already_done: bool,
    /// Why it did not run, when it did not. Safe to show a user verbatim.
    pub deferred: Option<&'static str>,
}

/// Re-seal any `.env` restore record an earlier build stored in plaintext
/// (`RA-006`), from whichever front end reaches an unlocked vault first.
///
/// # Why this is here and not in each application
///
/// ADR 0028 states the scrub runs at unlock in "`Ctx::unlocked`, and the
/// desktop's unlocked commands", and that this closes the gap for a user who
/// only ever uses the GUI. The desktop call site did not exist (`ENC-01`), so
/// the persona the ADR names as the reason this feature exists was the one
/// persona whose plaintext was never re-sealed. Both front ends now call THIS
/// function, so the claim cannot drift from one of them again.
///
/// Unlock is the right moment because it is the only one at which a key is
/// definitionally available: the read-only entry points hold no vault, and
/// redacting a legacy record without a key would destroy the user's ability
/// to undo the link.
///
/// Idempotent, transactional, resumable, and guarded by a marker so a
/// completed vault is never re-scanned. Best-effort at the call site: it must
/// never stop the command the user actually asked for — but it returns what
/// happened so a caller can surface a failure rather than swallow it.
pub fn upgrade_restore_records(vault: &mut UnlockedVault) -> Result<RestoreUpgrade> {
    let already: Option<String> = vault
        .connection()
        .query_row(
            "SELECT value FROM vault_meta WHERE key = ?1",
            [SCRUB_MARKER],
            |r| r.get(0),
        )
        .optional()?;
    if already.is_some() {
        return Ok(RestoreUpgrade {
            already_done: true,
            ..Default::default()
        });
    }
    let crypto = match vault.env_restore_crypto() {
        Ok(c) => c,
        Err(_) => {
            return Ok(RestoreUpgrade {
                deferred: Some(
                    "the restore-encryption key was not available; \
                     legacy rollback records will be re-sealed at the next unlock",
                ),
                ..Default::default()
            })
        }
    };
    let rewritten = scrub_stored_prior_env_once(vault.connection(), Some(&crypto))?;
    Ok(RestoreUpgrade {
        ran: true,
        rewritten,
        ..Default::default()
    })
}

/// Upgrade every stored restore record so it holds no plaintext value.
///
/// With a key, legacy v1 plaintext is **re-sealed** — the user keeps a
/// working undo and stops having a credential in a plain column. Without
/// one, it is redacted and marked withheld: losing the ability to restore
/// one line automatically is the right trade against leaving a credential
/// in the clear, and the user is told.
pub fn scrub_stored_prior_env(conn: &Connection, crypto: Option<&RestoreCrypto>) -> Result<usize> {
    let rows: Vec<(String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT link_slug, prior_env_json FROM gateway_project_links
             WHERE prior_env_json IS NOT NULL",
        )?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let mut out = Vec::new();
        for row in mapped {
            out.push(row?);
        }
        out
    };
    let mut scrubbed = 0usize;
    for (slug, json) in rows {
        // A record this build cannot parse (or that a newer build wrote) is
        // left exactly as it is rather than being destroyed by a guess.
        let Ok(mut parsed) = serde_json::from_str::<PriorEnv>(&json) else {
            continue;
        };
        if parsed.v > PRIOR_ENV_VERSION {
            continue;
        }
        let had_plaintext = parsed
            .files
            .iter()
            .flat_map(|f| &f.vars)
            .any(|v| v.prior.is_some() || !v.prior_all.is_empty());
        if !had_plaintext {
            continue;
        }
        if crypto.is_some() {
            parsed.files = seal_prior_files(crypto, &slug, std::mem::take(&mut parsed.files))?;
        } else {
            redact_all_plaintext(&mut parsed);
        }
        parsed.v = PRIOR_ENV_VERSION;
        let rewritten = serde_json::to_string(&parsed).map_err(CoreError::Serde)?;
        conn.execute(
            "UPDATE gateway_project_links SET prior_env_json = ?2 WHERE link_slug = ?1",
            params![slug, rewritten],
        )?;
        scrubbed += 1;
    }
    Ok(scrubbed)
}

/// Merge fresh per-file prior records over the stored ones: the FIRST
/// recorded prior for a (file, var) wins — a re-link must not overwrite the
/// original pre-Tethra value with Tethra's own earlier write.
fn merge_prior(stored: Vec<PriorFile>, fresh: Vec<PriorFile>) -> Vec<PriorFile> {
    let mut by_path: BTreeMap<String, PriorFile> = BTreeMap::new();
    for f in stored {
        by_path.insert(f.path.clone(), f);
    }
    for f in fresh {
        match by_path.get_mut(&f.path) {
            None => {
                by_path.insert(f.path.clone(), f);
            }
            Some(existing) => {
                for var in f.vars {
                    if !existing.vars.iter().any(|v| v.key == var.key) {
                        existing.vars.push(var);
                    } else if let Some(v) = existing.vars.iter_mut().find(|v| v.key == var.key) {
                        // Keep the ORIGINAL prior; refresh only `written` so
                        // user-edit detection tracks the latest write.
                        v.written = var.written;
                    }
                }
            }
        }
    }
    by_path.into_values().collect()
}

/// How one variable was handled during restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RestoreOutcome {
    /// Prior value put back (or the created line removed).
    Restored { path: String, key: String },
    /// The current value is neither what the writer wrote nor the prior —
    /// the user changed it after linking; left untouched.
    LeftUserEdit { path: String, key: String },
    /// Already at the prior state; nothing to do.
    AlreadyRestored { path: String, key: String },
    /// The file is gone; nothing to restore in it.
    FileMissing { path: String },
    /// A `.env` the link itself created was removed on restore, because
    /// nothing but the writer's own lines was ever in it.
    CreatedFileRemoved { path: String },
    /// The variable's prior value was never recorded (no key was available
    /// to seal it, so it was withheld rather than stored in the clear). The
    /// gateway line is left in place rather than deleted — restoring it is a
    /// manual step, and the link row is KEPT so the user still has the
    /// record and can unlink again once they have put their value back.
    PriorNotRecorded { path: String, key: String },
    /// The file could not be read or written.
    Failed {
        path: String,
        key: String,
        error: String,
    },
}

/// The unlink/disable restore report.
#[derive(Debug, Clone, Serialize)]
pub struct UnlinkReport {
    pub route_prefix: String,
    pub project_id: String,
    pub outcomes: Vec<RestoreOutcome>,
    /// Whether every variable ended in a settled state (see
    /// [`outcome_is_settled`]) and the link row was therefore removed.
    ///
    /// Callers render this as the word "restored", so it is derived from the
    /// outcomes rather than from the I/O error flag alone: an outcome that
    /// leaves the gateway's own line sitting in the user's `.env` without
    /// erroring is not a restore, whatever else went right (RA-013).
    pub complete: bool,
}

/// Whether one outcome leaves that variable genuinely settled — either back
/// at its pre-link state, or in a state no retry could improve.
///
/// Deliberately an exhaustive `match` rather than a "not Failed" test:
/// `complete` is what the desktop and the CLI turn into the word "restored"
/// AND the condition under which the link row (with its restore record) is
/// deleted, so a variant added later must not fall into that word by
/// omission. That omission is exactly what RA-013 was — `PriorNotRecorded`
/// never set the failure flag, so unlink answered `complete: true`, deleted
/// the only record of what had been changed, and left the `.env` still
/// pointing at the gateway while telling the user it had been restored.
fn outcome_is_settled(outcome: &RestoreOutcome) -> bool {
    match outcome {
        RestoreOutcome::Restored { .. }
        | RestoreOutcome::AlreadyRestored { .. }
        | RestoreOutcome::FileMissing { .. }
        | RestoreOutcome::CreatedFileRemoved { .. } => true,
        // The current value is neither the writer's nor the recorded prior:
        // the gateway's line is already GONE from the file, replaced by the
        // user's own value. Nothing is left to restore and a retry would do
        // the same nothing forever, so this settles the link — keeping the
        // row would make a link the user already fixed by hand permanently
        // un-unlinkable. This is the case `PriorNotRecorded` is not.
        RestoreOutcome::LeftUserEdit { .. } => true,
        // The line the WRITER wrote is still in the user's file — that is
        // the condition this outcome is produced under — and Tethra cannot
        // take it out, because it never kept the value that was there
        // before. Keep the row: the user needs it to see what was changed,
        // and unlinking again after they restore the value by hand then
        // completes properly.
        RestoreOutcome::PriorNotRecorded { .. } => false,
        RestoreOutcome::Failed { .. } => false,
    }
}

/// Restore the recorded prior state and remove the link row.
///
/// Restore is conservative in the user's favor: a value the user changed
/// AFTER linking is never overwritten (reported as `LeftUserEdit`), and a
/// failure to rewrite one file keeps the link row so the restore can be
/// retried — reported per file, never silently skipped (PRODUCT_BEHAVIOR:
/// disabling an optional feature must not brick a linked app).
///
/// "Retryable" is decided over the OUTCOMES, not over I/O errors alone: a
/// variable whose prior value was never recorded leaves the gateway's line
/// in the `.env` without any error at all, and the row is kept for it too.
pub fn unlink(
    conn: &Connection,
    crypto: Option<&RestoreCrypto>,
    project_id: &str,
    route_prefix: &str,
) -> Result<UnlinkReport> {
    let Some(link) = routes::find_project_link(conn, project_id, route_prefix)? else {
        return Err(CoreError::NotFound {
            kind: "gateway project link",
            ident: format!("{project_id}:{route_prefix}"),
        });
    };
    let mut outcomes = Vec::new();
    let mut any_failure = false;

    if let Some(json) = &link.prior_env_json {
        let prior: PriorEnv = serde_json::from_str(json).map_err(CoreError::Serde)?;
        check_prior_env_version(prior.v)?;
        for file in &prior.files {
            let opened = open_prior_file(crypto, &link.link_slug, file)?;
            restore_file(&opened, &mut outcomes, &mut any_failure);
        }
    }

    // `any_failure` covers only the errors `restore_file` itself raises, so
    // it can never see an outcome that failed to restore anything WITHOUT
    // erroring. `outcome_is_settled` is the classification that can.
    if any_failure || !outcomes.iter().all(outcome_is_settled) {
        // Keep the row (and its restore record) for a retry.
        return Ok(UnlinkReport {
            route_prefix: route_prefix.to_string(),
            project_id: project_id.to_string(),
            outcomes,
            complete: false,
        });
    }
    routes::remove_project_link(conn, project_id, route_prefix)?;
    audit::record(
        conn,
        "gateway_env_restored",
        Some(project_id),
        None,
        &format!("prefix={route_prefix}"),
    )?;
    Ok(UnlinkReport {
        route_prefix: route_prefix.to_string(),
        project_id: project_id.to_string(),
        outcomes,
        complete: true,
    })
}

fn restore_file(file: &PriorFile, outcomes: &mut Vec<RestoreOutcome>, any_failure: &mut bool) {
    let path = Path::new(&file.path);
    // `exists()` is false for ANY metadata error — a permission change on the
    // parent directory, an unmounted volume, an fd-exhausted process. Treating
    // those as "the user deleted it" would drop the restore record (the only
    // copy of the prior values) permanently, so only a genuine NotFound is
    // allowed to be terminal; everything else keeps the row for a retry.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            // Link time REFUSES a symlink because an atomic rename replaces
            // the link rather than its target. The same must hold here: a
            // file that became a symlink after linking must not have that
            // link silently destroyed by the restore.
            *any_failure = true;
            outcomes.push(RestoreOutcome::Failed {
                path: file.path.clone(),
                key: String::new(),
                error: "the file is now a symlink; refusing to replace it \
                        (restore the target file by hand, then unlink again)"
                    .into(),
            });
            return;
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            outcomes.push(RestoreOutcome::FileMissing {
                path: file.path.clone(),
            });
            return;
        }
        Err(e) => {
            *any_failure = true;
            outcomes.push(RestoreOutcome::Failed {
                path: file.path.clone(),
                key: String::new(),
                error: e.to_string(),
            });
            return;
        }
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            *any_failure = true;
            outcomes.push(RestoreOutcome::Failed {
                path: file.path.clone(),
                key: String::new(),
                error: e.to_string(),
            });
            return;
        }
    };
    let mut doc = EnvDocument::parse(&content);
    let mut changed = false;
    for var in &file.vars {
        let current = doc.get(&var.key).map(|e| e.value.expose().to_string());
        match (&current, &var.prior) {
            (None, None) => outcomes.push(RestoreOutcome::AlreadyRestored {
                path: file.path.clone(),
                key: var.key.clone(),
            }),
            (Some(cur), _) if *cur == var.written && var.prior_withheld => {
                // The prior value was deliberately not recorded (it did not
                // look like non-secret configuration). Say so; do NOT delete
                // the line, which would destroy what is still there.
                outcomes.push(RestoreOutcome::PriorNotRecorded {
                    path: file.path.clone(),
                    key: var.key.clone(),
                });
            }
            (Some(cur), prior) if *cur == var.written => {
                // Still exactly what the writer wrote: restore.
                match prior {
                    Some(p) => {
                        if var.prior_all.len() > 1 {
                            doc.set_each_occurrence(&var.key, &var.prior_all);
                        } else {
                            doc.set(&var.key, SecretString::new(p.clone()));
                        }
                        doc.remove_marker_above(&var.key);
                    }
                    None => {
                        doc.remove_with_comment(&var.key);
                    }
                }
                changed = true;
                outcomes.push(RestoreOutcome::Restored {
                    path: file.path.clone(),
                    key: var.key.clone(),
                });
            }
            (Some(cur), Some(p)) if cur == p => {
                // Already back at the prior value (user restored by hand);
                // just drop any leftover marker.
                if doc.remove_marker_above(&var.key) {
                    changed = true;
                }
                outcomes.push(RestoreOutcome::AlreadyRestored {
                    path: file.path.clone(),
                    key: var.key.clone(),
                });
            }
            _ => outcomes.push(RestoreOutcome::LeftUserEdit {
                path: file.path.clone(),
                key: var.key.clone(),
            }),
        }
    }
    if changed {
        // A file the LINK created, with nothing left in it, is removed —
        // `PriorFile.existed` promised exactly that and nothing read it, so
        // linking a project with no .env left an empty file behind forever.
        // "Nothing left" means no entries at all: any variable the user
        // added after linking keeps the file.
        if !file.existed && doc.entries().next().is_none() {
            match std::fs::remove_file(path) {
                Ok(()) => outcomes.push(RestoreOutcome::CreatedFileRemoved {
                    path: file.path.clone(),
                }),
                Err(e) => {
                    *any_failure = true;
                    outcomes.push(RestoreOutcome::Failed {
                        path: file.path.clone(),
                        key: String::new(),
                        error: e.to_string(),
                    });
                }
            }
            return;
        }
        if let Err(e) = envgov::atomic_write(path, &doc.render()) {
            *any_failure = true;
            outcomes.push(RestoreOutcome::Failed {
                path: file.path.clone(),
                key: String::new(),
                error: e.to_string(),
            });
        }
        // Same reason as the link path above (`NEW-29`): unlink rewrites the
        // user's `.env` atomically and can orphan the same temp file.
        if let Some(dir) = path.parent() {
            envgov::sweep_orphaned_temp_files_in(dir);
        }
    }
}

/// What `complete` is allowed to mean (RA-013).
///
/// The `tests/envlink.rs` suite covers the restore mechanics; these two
/// cover the *verdict* the desktop and the CLI turn into the word
/// "restored", including the one state that produced that word while the
/// gateway's line was still in the user's file.
#[cfg(test)]
mod restore_completeness_tests {
    use super::*;
    use api_tracker_core::db;
    use api_tracker_core::secret::SecretBytes;

    /// A deterministic, unmistakably fake restore-record key.
    fn crypto() -> RestoreCrypto {
        RestoreCrypto::new(
            "vault-test-0001".to_string(),
            SecretBytes::new(vec![0x2au8; 32]),
        )
    }

    /// A vault with an openai route, a persisted port and a project row —
    /// the minimum `apply_link` needs.
    fn linkable(dir: &Path) -> Connection {
        let mut conn = db::open(&dir.join("vault.db")).unwrap();
        db::migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('vault_id', 'vault-test-0001')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO projects (id, name, description, notes, environments, archived,
                 created_at, updated_at, wrapped_project_key, key_wrap_mode)
             VALUES ('p1', 'app', '', '', 'development', 0,
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', x'00', 'vault')",
            [],
        )
        .unwrap();
        routes::add_manifest_route(&conn, "openai", "openai").unwrap();
        let mut config = store::load_config(&conn).unwrap();
        config.port = Some(49723);
        store::save_config(&conn, &config).unwrap();
        conn
    }

    fn request(env_file: &Path) -> LinkRequest {
        LinkRequest {
            project_id: "p1".into(),
            project_name: "app".into(),
            route_prefix: "openai".into(),
            project_dir: None,
            files: vec![env_file.to_path_buf()],
            var_override: None,
        }
    }

    const PRIOR: &str = "OPENAI_BASE_URL=https://corp-proxy.example/v1\n";

    #[test]
    fn an_unrecorded_prior_is_not_a_restore_and_keeps_the_link_row() {
        let dir = tempfile::tempdir().unwrap();
        let conn = linkable(dir.path());
        let env = dir.path().join(".env");
        std::fs::write(&env, PRIOR).unwrap();
        let req = request(&env);

        // Linking with no key WITHHOLDS the prior value rather than storing
        // it in the clear (RA-006) — which is exactly the state a later
        // unlink cannot undo, however well the unlink itself goes.
        let plan = plan_link(&conn, &req).unwrap();
        apply_link(&conn, None, &req, &plan).unwrap();
        assert!(std::fs::read_to_string(&env).unwrap().contains("127.0.0.1"));

        // A key at unlink time cannot conjure a value that was never
        // recorded, so this is the honest best case, not a degraded one.
        let report = unlink(&conn, Some(&crypto()), "p1", "openai").unwrap();

        assert!(
            report.outcomes.iter().any(|o| matches!(
                o,
                RestoreOutcome::PriorNotRecorded { key, .. } if key == "OPENAI_BASE_URL"
            )),
            "expected a PriorNotRecorded outcome, got {:?}",
            report.outcomes
        );
        assert!(
            !report.complete,
            "unlink claimed a completed restore while the value it could not \
             restore was still withheld: {report:?}"
        );
        assert!(
            std::fs::read_to_string(&env).unwrap().contains("127.0.0.1"),
            "the gateway's line is still in the file — which is why the report \
             must not say 'restored'"
        );
        assert!(
            routes::find_project_link(&conn, "p1", "openai")
                .unwrap()
                .is_some(),
            "the link row (and its restore record) must survive so the user \
             can still see what was changed and retry"
        );
    }

    /// The negative control for the test above: with the prior value actually
    /// recorded, the SAME setup must still reach `complete: true` and drop the
    /// row. Without this, `outcome_is_settled` could return false for every
    /// variant — or `linkable` could be silently broken — and the regression
    /// test would still pass.
    #[test]
    fn control_a_recorded_prior_completes_and_removes_the_link_row() {
        let dir = tempfile::tempdir().unwrap();
        let conn = linkable(dir.path());
        let env = dir.path().join(".env");
        std::fs::write(&env, PRIOR).unwrap();
        let req = request(&env);

        let plan = plan_link(&conn, &req).unwrap();
        apply_link(&conn, Some(&crypto()), &req, &plan).unwrap();
        assert!(std::fs::read_to_string(&env).unwrap().contains("127.0.0.1"));

        let report = unlink(&conn, Some(&crypto()), "p1", "openai").unwrap();

        assert!(report.complete, "{report:?}");
        assert_eq!(std::fs::read_to_string(&env).unwrap(), PRIOR);
        assert!(routes::find_project_link(&conn, "p1", "openai")
            .unwrap()
            .is_none());
    }
}
