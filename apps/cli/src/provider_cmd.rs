//! `provider` subcommands: browse the catalog and manage documentation
//! watches. Catalog reads need no vault; doc watches use the local database.

use crate::ctx::Ctx;
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::docwatch::{CheckResult, HttpFetcher};
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
                    "Provider API connectors (validation, usage, permissions) are not \
                     implemented yet; see `provider capabilities <id>` for honest status."
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
                println!("Capabilities for {} (nothing is implemented yet):", m.name);
                println!();
                render::print_capabilities(&m.capabilities);
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
