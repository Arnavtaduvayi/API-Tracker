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
use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::secret::SecretString;
use api_tracker_core::{audit, envgov, providers};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::routes;
use crate::store;

/// The current `prior_env_json` document version.
const PRIOR_ENV_VERSION: u32 = 1;

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
    /// The value before linking; `None` when the variable did not exist OR
    /// when it did not look like non-secret configuration (see
    /// `prior_withheld`). `prior_env_json` is a PLAINTEXT column, so only
    /// values that are safe there are recorded (D9).
    pub prior: Option<String>,
    /// The variable existed but its value was NOT recorded, because it did
    /// not look like a base URL or proxy list — `--var` accepts any name, so
    /// the prior value can be an API key, and a base URL can carry userinfo.
    /// Restore reports this honestly instead of silently writing nothing.
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
}

/// Whether a prior `.env` value is safe to record in the plaintext
/// `prior_env_json` column.
///
/// Deliberately a strict allowlist rather than a secret-detector: the column
/// is plaintext and the cost of being wrong is a stored credential, while the
/// cost of being conservative is one line the user restores by hand. A value
/// qualifies only if it is an `http`/`https` URL with no userinfo, or a
/// proxy-list-shaped value (comma-separated hosts/IPs/suffixes).
pub fn prior_value_is_recordable(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    if let Some(rest) = v
        .strip_prefix("http://")
        .or_else(|| v.strip_prefix("https://"))
    {
        // `user:pass@host` in a base URL is a credential.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        return !authority.contains('@');
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

/// A complete, previewable link plan. `digest` binds the previewed content:
/// apply re-plans and refuses if anything changed underneath the preview.
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
    /// BLAKE3 over every planned output, hex. Binds preview to apply.
    pub digest: String,
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
    let vars = link_vars(&provider_id, req.var_override.as_deref())?;

    let config = store::load_config(conn)?;
    let Some(port) = config.port else {
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
        let plan = plan_file(path, req, &vars, &base_url, &marker, port)?;
        all_warnings.extend(plan.warnings.clone());
        plans.push(plan);
    }
    project_level_warnings(req, &mut all_warnings);

    let mut hasher = blake3::Hasher::new();
    hasher.update(link_slug.as_bytes());
    for p in &plans {
        hasher.update(p.path.as_bytes());
        hasher.update(p.new_content.as_bytes());
    }
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
        digest: hasher.finalize().to_hex().to_string(),
    })
}

/// Apply a previously previewed plan. Re-plans internally and refuses when
/// any file changed since the preview (`digest` mismatch), so what the user
/// confirmed is exactly what is written.
pub fn apply_link(conn: &Connection, req: &LinkRequest, approved: &LinkPlan) -> Result<PriorEnv> {
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
    let prior = PriorEnv {
        v: PRIOR_ENV_VERSION,
        port: replanned.port,
        files: merge_prior(
            existing_prior(conn, &replanned.link_slug)?,
            replanned.files.iter().map(|f| f.prior.clone()).collect(),
        ),
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
            let fp = plan_file(path, req, &plan.vars, &base_url, &marker, plan.port)?;
            warnings.extend(fp.warnings.clone());
            plans.push(fp);
        }
        project_level_warnings(req, &mut warnings);
        let mut hasher = blake3::Hasher::new();
        hasher.update(slug.as_bytes());
        for p in &plans {
            hasher.update(p.path.as_bytes());
            hasher.update(p.new_content.as_bytes());
        }
        plan.link_slug = slug.to_string();
        plan.base_url = base_url;
        plan.files = plans;
        plan.warnings = warnings;
        plan.digest = hasher.finalize().to_hex().to_string();
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

/// Plan the rewrite of one file, collecting warnings.
fn plan_file(
    path: &Path,
    req: &LinkRequest,
    vars: &[String],
    base_url: &str,
    marker: &str,
    _port: u16,
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

    let exists = path.exists();
    let old_content = if exists {
        std::fs::read_to_string(path).map_err(CoreError::Io)?
    } else {
        String::new()
    };
    let mut doc = EnvDocument::parse(&old_content);
    let path_str = path.display().to_string();
    let mut warnings = Vec::new();

    file_warnings(path, &path_str, req, exists, &doc, &mut warnings);

    let mut prior_vars = Vec::new();
    for var in vars {
        let existing = doc.get(var).map(|e| e.value.expose().to_string());
        // `prior_env_json` is plaintext. `--var` accepts ANY variable name,
        // and a declared base-URL variable can hold a URL with embedded
        // credentials, so a prior value is only recorded when it looks like
        // non-secret configuration.
        let recordable = existing.as_deref().is_none_or(prior_value_is_recordable);
        if let Some(prior) = &existing {
            if !recordable {
                warnings.push(LinkWarning::PriorValueWithheld {
                    path: path_str.clone(),
                    key: var.clone(),
                });
            } else if prior != base_url {
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
        let prior_all =
            if all.len() > 1 && recordable && all.iter().all(|v| prior_value_is_recordable(v)) {
                all
            } else {
                Vec::new()
            };
        prior_vars.push(PriorVar {
            key: var.clone(),
            prior_withheld: existing.is_some() && !recordable,
            prior: if recordable { existing } else { None },
            prior_all,
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
            prior_withheld: false,
            prior_all: Vec::new(),
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
                prior_vars.push(PriorVar {
                    key: key.clone(),
                    prior: Some(current),
                    prior_withheld: false,
                    prior_all: Vec::new(),
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

fn existing_prior(conn: &Connection, slug: &str) -> Result<Vec<PriorFile>> {
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
    let parsed: PriorEnv = serde_json::from_str(&json).map_err(CoreError::Serde)?;
    check_prior_env_version(parsed.v)?;
    Ok(parsed.files)
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
    /// The variable's prior value was never recorded (it did not look like
    /// non-secret configuration, so it was kept out of the plaintext restore
    /// record). The gateway line is left in place rather than deleted —
    /// restoring it is a manual step.
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
    /// Whether every file ended in a fully-restored (or missing) state and
    /// the link row was removed.
    pub complete: bool,
}

/// Restore the recorded prior state and remove the link row.
///
/// Restore is conservative in the user's favor: a value the user changed
/// AFTER linking is never overwritten (reported as `LeftUserEdit`), and a
/// failure to rewrite one file keeps the link row so the restore can be
/// retried — reported per file, never silently skipped (PRODUCT_BEHAVIOR:
/// disabling an optional feature must not brick a linked app).
pub fn unlink(conn: &Connection, project_id: &str, route_prefix: &str) -> Result<UnlinkReport> {
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
            restore_file(file, &mut outcomes, &mut any_failure);
        }
    }

    if any_failure {
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
    }
}
