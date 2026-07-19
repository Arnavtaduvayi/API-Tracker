//! `provider` subcommands: browse the catalog and manage documentation
//! watches. Catalog reads need no vault; doc watches use the local database.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::docwatch::{CheckResult, HttpFetcher};
use api_tracker_core::http::UreqClient;
use api_tracker_core::providers;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum ProviderCmd {
    /// List known providers.
    List,
    /// Show a provider's details and links.
    Show { provider: String },
    /// Print a provider's official documentation and management links.
    Docs { provider: String },
    /// Show a provider's capability matrix (honest support levels).
    Capabilities { provider: String },
    /// Show (or --sync) provider-reported account identity for a
    /// connection. Only official endpoints; OpenAI reports none and the
    /// user-entered organization label stands in, labeled as such.
    Account {
        provider: String,
        /// Fetch fresh account identity from the provider now.
        #[arg(long)]
        sync: bool,
    },
    /// Connect a provider's administrative account for usage/cost sync.
    /// Prompts for the admin key (OpenAI Admin API key) and stores it
    /// encrypted in the vault; it can later be replaced or removed but never
    /// displayed. Pass --credential to reference an existing vault
    /// credential instead.
    Connect {
        provider: String,
        /// Use an existing vault credential (project/name) as the admin key.
        #[arg(long)]
        credential: Option<String>,
        /// Optional organization label recorded with the connection.
        #[arg(long)]
        org: Option<String>,
        /// Read the admin key from stdin (for scripts) instead of prompting.
        #[arg(long)]
        key_stdin: bool,
        /// Store without a live validation request (offline setup); verify
        /// later with `provider test`.
        #[arg(long)]
        no_verify: bool,
    },
    /// Remove a provider connection and its locally stored administrative
    /// access (requires confirmation and reauthentication). Synced usage
    /// stays available offline.
    Disconnect {
        provider: String,
        #[arg(long)]
        yes: bool,
    },
    /// Live administrative connection test (network request; requires
    /// reauthentication).
    Test { provider: String },
    /// Sync usage and provider-reported costs from a connected provider
    /// (network request). Default: incremental from the last checkpoint
    /// (first sync covers 30 days).
    Sync {
        provider: String,
        /// Look back exactly this many days instead.
        #[arg(long, conflicts_with_all = ["from", "to"])]
        days: Option<u32>,
        /// Explicit window start (YYYY-MM-DD or RFC 3339).
        #[arg(long)]
        from: Option<String>,
        /// Explicit window end (defaults to now).
        #[arg(long, requires = "from")]
        to: Option<String>,
    },
    /// Show a provider's connection status.
    ConnectionStatus { provider: String },
    /// List provider-side API keys seen in metadata and synced usage, with
    /// their local link state and any suggested association.
    Keys { provider: String },
    /// Confirm that a provider-side API-key id belongs to a local credential.
    /// Existing synced rows are re-attributed as exact-credential.
    Link {
        provider: String,
        api_key_id: String,
        #[arg(long)]
        credential: String,
    },
    /// Remove a provider-key association (rows honestly downgrade back to
    /// provider-key attribution).
    Unlink {
        provider: String,
        api_key_id: String,
        #[arg(long)]
        yes: bool,
    },
    /// List provider-side projects with month-to-date reported cost and
    /// local mapping state.
    Projects { provider: String },
    /// Watch an official documentation URL for changes.
    WatchDocs {
        provider: String,
        /// URL to watch (defaults to the provider's documented watch URLs).
        #[arg(long)]
        url: Option<String>,
    },
    /// Stop watching a URL.
    UnwatchDocs { provider: String, url: String },
    /// Check watched documentation for changes now (makes a network request).
    CheckDocs {
        provider: String,
        /// Check every watched URL, not just this provider's.
        #[arg(long)]
        all: bool,
    },
    /// Show documentation-watch status.
    DocsStatus { provider: Option<String> },
    /// Show the documentation change history (validators only).
    DocsHistory {
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value_t = 30)]
        limit: u32,
    },
}

fn find(provider: &str) -> Result<&'static providers::ProviderManifest> {
    providers::find(provider)
        .ok_or_else(|| anyhow::anyhow!("unknown provider '{provider}'. Try `provider list`."))
}

pub fn run(ctx: &Ctx, cmd: ProviderCmd) -> Result<()> {
    match cmd {
        ProviderCmd::List => {
            let manifests = providers::manifests();
            render::emit(ctx.json, &manifests, || {
                let rows: Vec<Vec<String>> = manifests
                    .iter()
                    .map(|m| {
                        vec![
                            m.id.clone(),
                            m.name.clone(),
                            m.env_vars.join(","),
                            m.detection.len().to_string(),
                        ]
                    })
                    .collect();
                render::table(&["ID", "NAME", "SECRET ENV VARS", "PATTERNS"], &rows);
                println!();
                println!(
                    "Capability support varies per provider — see `provider capabilities <id>` \
                     for honest, per-capability status."
                );
            });
        }
        ProviderCmd::Show { provider } => {
            let m = find(&provider)?;
            render::emit(ctx.json, m, || render::print_provider(m));
        }
        ProviderCmd::Docs { provider } => {
            let m = find(&provider)?;
            render::emit(ctx.json, &m.watch_docs, || {
                println!("Provider:        {}", m.name);
                println!("API docs:        {}", m.api_docs_url);
                println!("Auth docs:       {}", m.auth_docs_url);
                println!("Manage keys:     {}", m.manage_url);
                if !m.login_url.is_empty() {
                    println!("Console login:   {}", m.login_url);
                }
                if !m.billing_url.is_empty() {
                    println!("Billing portal:  {}", m.billing_url);
                }
                println!("Website:         {}", m.website);
                if !m.watch_docs.is_empty() {
                    println!("Watchable pages:");
                    for url in &m.watch_docs {
                        println!("  - {url}");
                    }
                }
            });
        }
        ProviderCmd::Capabilities { provider } => {
            let m = find(&provider)?;
            render::emit(ctx.json, &m.capabilities, || {
                println!("Capabilities for {} (honest support levels):", m.name);
                println!();
                render::print_capabilities(&m.capabilities);
            });
        }
        ProviderCmd::Connect {
            provider,
            credential,
            org,
            key_stdin,
            no_verify,
        } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            if let Some(credential) = credential {
                vault.provider_connect(&m.id, &credential)?;
                println!(
                    "Connected {} using vault credential '{credential}' as its admin key.",
                    m.name
                );
                return Ok(());
            }
            let existing = vault.provider_connection_status(&m.id)?;
            if existing.connected {
                eprintln!("Reauthentication required to replace the administrative connection.");
                let password = ctx::master_password()?;
                vault.verify_master_password(&password)?;
            }
            eprintln!(
                "NOTE: this stores an ADMINISTRATIVE key with organization-wide access — \
                 not an ordinary workload API key. It is encrypted locally, used only for \
                 direct requests to {}, and can be removed with `provider disconnect {}`.",
                m.name, m.id
            );
            let key = ctx::provider_admin_key(key_stdin)?;
            let detail = if no_verify {
                vault.provider_admin_connect(&m.id, &key, org.as_deref(), None)?
            } else {
                let http = UreqClient::new();
                vault.provider_admin_connect(&m.id, &key, org.as_deref(), Some(&http))?
            };
            println!("Connected {}: {detail}", m.name);
            println!(
                "Run `api-tracker provider sync {}` to synchronize usage.",
                m.id
            );
        }
        ProviderCmd::Disconnect { provider, yes } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            if !ctx::confirm(
                &format!(
                    "Remove the {} connection and its locally stored administrative access?",
                    m.name
                ),
                yes,
            )? {
                bail!("aborted");
            }
            eprintln!("Reauthentication required to remove the administrative connection.");
            let password = ctx::master_password()?;
            vault.verify_master_password(&password)?;
            if vault.provider_admin_disconnect(&m.id)? {
                println!(
                    "Disconnected {}. Previously synced usage remains viewable offline.",
                    m.name
                );
            } else {
                println!("{} was not connected.", m.name);
            }
        }
        ProviderCmd::Test { provider } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            eprintln!("Reauthentication required to run a live connection test.");
            let password = ctx::master_password()?;
            vault.verify_master_password(&password)?;
            let http = UreqClient::new();
            let detail = vault.provider_admin_test(&m.id, &http)?;
            println!("{}: {detail}", m.name);
        }
        ProviderCmd::Sync {
            provider,
            days,
            from,
            to,
        } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            let http = UreqClient::new();
            let report = if let Some(from) = from {
                let from_ts = api_tracker_core::clock::parse_user_date(&from)?;
                let to_ts = match to {
                    Some(t) => api_tracker_core::clock::parse_user_date(&t)?,
                    None => api_tracker_core::clock::now(),
                };
                vault.usage_sync_range(&m.id, &http, from_ts, to_ts)?
            } else if let Some(days) = days {
                vault.usage_sync(&m.id, &http, days)?
            } else {
                vault.usage_sync_default(&m.id, &http)?
            };
            let status = vault.provider_connection_status(&m.id)?;
            render::emit(ctx.json, &report, || {
                println!(
                    "Synced {} usage row(s) and {} provider-reported cost row(s) for {}.",
                    report.usage_rows, report.cost_rows, m.name
                );
                println!("Window: {} → {}", report.window_start, report.window_end);
                for note in &report.notes {
                    println!("NOTE: {note}");
                }
                println!(
                    "Last successful sync: {}",
                    status.last_success_at.as_deref().unwrap_or("never")
                );
            });
        }
        ProviderCmd::ConnectionStatus { provider } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            let status = vault.provider_connection_status(&m.id)?;
            render::emit(ctx.json, &status, || {
                println!("Provider:      {}", m.name);
                if let Some(masked) = &status.admin_key_masked {
                    println!("Admin key:     {masked} (administrative, encrypted at rest)");
                } else if let Some(cred) = &status.admin_credential_id {
                    println!("Admin key:     vault credential {cred}");
                } else {
                    println!("Admin key:     (not connected)");
                }
                if let Some(org) = &status.org_label {
                    println!("Organization:  {org}");
                }
                println!(
                    "Connected at:  {}",
                    status.connected_at.as_deref().unwrap_or("-")
                );
                println!(
                    "Last success:  {}",
                    status.last_success_at.as_deref().unwrap_or("never")
                );
                println!(
                    "Last failure:  {}",
                    status.last_failure_at.as_deref().unwrap_or("never")
                );
                println!("Last status:   {}", status.last_status);
                if !status.detail.is_empty() {
                    println!("Detail:        {}", status.detail);
                }
                if !status.last_error.is_empty() {
                    println!("Last error:    {}", status.last_error);
                }
                if let Some(at) = &status.account_synced_at {
                    println!(
                        "Account:       {} <{}> id={} plan={}",
                        status.account_name.as_deref().unwrap_or("-"),
                        status.account_email.as_deref().unwrap_or("-"),
                        status.account_id.as_deref().unwrap_or("-"),
                        status.account_plan.as_deref().unwrap_or("-"),
                    );
                    println!(
                        "               provider-reported via {} at {at}",
                        status.account_source.as_deref().unwrap_or("?")
                    );
                } else if status.connected {
                    println!(
                        "Account:       not synced (run `provider account {} --sync`)",
                        m.id
                    );
                }
                if status.stale {
                    println!(
                        "WARNING: synced data is STALE — run `api-tracker provider sync {}`.",
                        m.id
                    );
                }
            });
        }
        ProviderCmd::Account { provider, sync } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            if sync {
                let http = api_tracker_core::http::UreqClient::new();
                let info = vault.provider_account_sync(&m.id, &http)?;
                println!(
                    "Synced account identity from {} — every field below is \
                     provider-reported.",
                    info.source
                );
            }
            let status = vault.provider_connection_status(&m.id)?;
            render::emit(ctx.json, &status, || {
                println!("Provider:  {}", m.name);
                match &status.account_synced_at {
                    Some(at) => {
                        println!(
                            "Name:      {}",
                            render::sanitize(status.account_name.as_deref().unwrap_or("-"))
                        );
                        println!(
                            "Email:     {}",
                            render::sanitize(status.account_email.as_deref().unwrap_or("-"))
                        );
                        println!(
                            "Id:        {}",
                            render::sanitize(status.account_id.as_deref().unwrap_or("-"))
                        );
                        println!(
                            "Plan:      {}",
                            render::sanitize(status.account_plan.as_deref().unwrap_or("-"))
                        );
                        println!(
                            "Source:    {} (provider-reported, synced {at})",
                            status.account_source.as_deref().unwrap_or("?")
                        );
                    }
                    None => println!(
                        "No provider-reported account identity stored. Run with --sync \
                         (needs a connection: `provider connect {}`).",
                        m.id
                    ),
                }
                if let Some(org) = &status.org_label {
                    println!("Org label: {} (user-entered, not provider-verified)", org);
                }
                if !m.login_url.is_empty() {
                    println!("Login:     {}", m.login_url);
                }
                if !m.billing_url.is_empty() {
                    println!("Billing:   {}", m.billing_url);
                }
                println!("Manage:    {}", m.manage_url);
            });
        }
        ProviderCmd::Keys { provider } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            let keys = vault.provider_keys_overview(&m.id)?;
            render::emit(ctx.json, &keys, || {
                if keys.is_empty() {
                    println!(
                        "No provider-side API keys known yet. Run `provider sync {}` first.",
                        m.id
                    );
                    return;
                }
                let rows: Vec<Vec<String>> = keys
                    .iter()
                    .map(|k| {
                        vec![
                            k.api_key_id.clone(),
                            k.name.clone(),
                            k.provider_project_name
                                .clone()
                                .or_else(|| k.provider_project_id.clone())
                                .unwrap_or_default(),
                            k.linked_credential
                                .clone()
                                .unwrap_or_else(|| "(not linked)".into()),
                            k.usage_rows.to_string(),
                            k.suggested_credential.clone().unwrap_or_default(),
                        ]
                    })
                    .collect();
                render::table(
                    &[
                        "API KEY ID",
                        "NAME",
                        "PROJECT",
                        "LINKED TO",
                        "ROWS",
                        "SUGGESTION",
                    ],
                    &rows,
                );
                for k in &keys {
                    if !k.note.is_empty() {
                        println!(
                            "  {}: {}",
                            render::sanitize(&k.api_key_id),
                            render::sanitize(&k.note)
                        );
                    }
                }
                println!();
                println!(
                    "Suggestions are evidence only — confirm with \
                     `provider link {} <api-key-id> --credential <project/name>`.",
                    m.id
                );
            });
        }
        ProviderCmd::Link {
            provider,
            api_key_id,
            credential,
        } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            let updated = vault.provider_link_key(&m.id, &api_key_id, &credential)?;
            println!(
                "Linked {} key {api_key_id} to '{credential}'. {updated} synced row(s) are now \
                 attributed as exact-credential.",
                m.name
            );
        }
        ProviderCmd::Unlink {
            provider,
            api_key_id,
            yes,
        } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            if !ctx::confirm(
                &format!(
                    "Unlink {} key {api_key_id} from its local credential?",
                    m.name
                ),
                yes,
            )? {
                bail!("aborted");
            }
            let updated = vault.provider_unlink_key(&m.id, &api_key_id)?;
            if updated == 0 {
                println!("No link existed for {api_key_id}.");
            } else {
                println!("Unlinked. {updated} row(s) downgraded to provider-key attribution.");
            }
        }
        ProviderCmd::Projects { provider } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            let projects = vault.provider_projects_overview(&m.id)?;
            render::emit(ctx.json, &projects, || {
                if projects.is_empty() {
                    println!(
                        "No provider-side projects known yet. Run `provider sync {}` first.",
                        m.id
                    );
                    return;
                }
                let rows: Vec<Vec<String>> = projects
                    .iter()
                    .map(|p| {
                        vec![
                            p.provider_project_id.clone(),
                            p.name.clone(),
                            api_tracker_core::usage::format_micros(p.reported_cost_micros_month),
                            if p.has_linked_usage {
                                "yes".into()
                            } else {
                                "no".into()
                            },
                        ]
                    })
                    .collect();
                render::table(
                    &[
                        "PROVIDER PROJECT",
                        "NAME",
                        "COST (MONTH, REPORTED)",
                        "LINKED USAGE",
                    ],
                    &rows,
                );
            });
        }
        ProviderCmd::WatchDocs { provider, url } => {
            let m = find(&provider)?;
            let (vault, _t) = ctx.unlocked()?;
            let urls: Vec<String> = match url {
                Some(u) => vec![u],
                None => {
                    if m.watch_docs.is_empty() {
                        bail!("{} has no default watch URLs; pass --url", m.name);
                    }
                    m.watch_docs.clone()
                }
            };
            for u in &urls {
                vault.watch_docs(&m.id, u)?;
                println!("Watching {u}");
            }
            println!(
                "Run `api-tracker provider check-docs {}` to check them (respects conditional \
                 requests and conservative intervals).",
                m.id
            );
        }
        ProviderCmd::UnwatchDocs { provider: _, url } => {
            let (vault, _t) = ctx.unlocked()?;
            if vault.unwatch_docs(&url)? {
                println!("Stopped watching {url}");
            } else {
                println!("No watch was registered for {url}");
            }
        }
        ProviderCmd::CheckDocs { provider, all } => {
            let (vault, _t) = ctx.unlocked()?;
            let watches = if all {
                vault.list_doc_watches()?
            } else {
                let m = find(&provider)?;
                vault.list_doc_watches_for(&m.id)?
            };
            if watches.is_empty() {
                println!(
                    "No documentation watches registered. Add one with `provider watch-docs`."
                );
                return Ok(());
            }
            let fetcher = HttpFetcher::new();
            let mut results = Vec::new();
            for w in watches {
                let (result, watch) = vault.check_doc_watch(&fetcher, &w.url)?;
                if !ctx.json {
                    let marker = match result {
                        CheckResult::Changed => "CHANGED",
                        CheckResult::FirstCapture => "captured",
                        CheckResult::Unchanged => "unchanged",
                        CheckResult::Failed => "failed",
                    };
                    println!("[{marker}] {}", watch.url);
                    if result == CheckResult::Changed {
                        println!(
                            "  The tracked content changed. This does NOT necessarily mean a \
                             breaking API change — review the page: {}",
                            watch.url
                        );
                    }
                }
                results.push(watch);
            }
            if ctx.json {
                render::emit(true, &results, || {});
            }
        }
        ProviderCmd::DocsHistory { url, limit } => {
            let (vault, _t) = ctx.unlocked()?;
            let history = vault.doc_watch_history(url.as_deref(), limit)?;
            render::emit(ctx.json, &history, || {
                if history.is_empty() {
                    println!("No documentation checks recorded yet.");
                    return;
                }
                let rows: Vec<Vec<String>> = history
                    .iter()
                    .map(|h| vec![h.at.clone(), h.outcome.clone(), h.url.clone()])
                    .collect();
                render::table(&["AT", "OUTCOME", "URL"], &rows);
            });
        }
        ProviderCmd::DocsStatus { provider } => {
            let (vault, _t) = ctx.unlocked()?;
            let watches = match &provider {
                Some(p) => vault.list_doc_watches_for(&find(p)?.id)?,
                None => vault.list_doc_watches()?,
            };
            render::emit(ctx.json, &watches, || {
                if watches.is_empty() {
                    println!("No documentation watches registered.");
                } else {
                    let rows: Vec<Vec<String>> = watches
                        .iter()
                        .map(|w| {
                            vec![
                                w.provider.clone(),
                                w.last_status.clone(),
                                w.last_checked_at.clone().unwrap_or_else(|| "never".into()),
                                w.url.clone(),
                            ]
                        })
                        .collect();
                    render::table(&["PROVIDER", "STATUS", "LAST CHECKED", "URL"], &rows);
                }
            });
        }
    }
    Ok(())
}
