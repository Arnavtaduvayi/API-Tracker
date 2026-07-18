//! Human-readable and JSON output. Credential values never pass through
//! here: models carry only masked values, and the one deliberate exception
//! (`key reveal`) prints directly in its command handler.

use api_tracker_core::model::{Credential, Project};
use api_tracker_core::providers::{Capabilities, ProviderManifest};
use api_tracker_core::reuse::ReuseWarning;
use api_tracker_core::status::StatusReport;
use serde::Serialize;

pub fn emit<T: Serialize>(json: bool, value: &T, human: impl FnOnce()) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).expect("models serialize infallibly")
        );
    } else {
        human();
    }
}

/// Strip control characters (incl. ANSI escape introducers) from a cell.
/// Provider-controlled strings (key names, event types, units) reach the
/// terminal through here; a compromised provider account must not be able
/// to inject escape sequences.
fn sanitize_cell(cell: &str) -> String {
    cell.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Minimal fixed-width table.
pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(|c| sanitize_cell(c)).collect())
        .collect();
    let rows = &rows;
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let mut out = String::new();
        for (i, cell) in cells.iter().enumerate() {
            out.push_str(cell);
            if i + 1 < cells.len() {
                out.push_str(&" ".repeat(widths[i].saturating_sub(cell.chars().count()) + 2));
            }
        }
        println!("{}", out.trim_end());
    };
    line(headers.iter().map(|h| h.to_string()).collect());
    line(widths.iter().map(|w| "-".repeat(*w)).collect());
    for row in rows {
        line(row.clone());
    }
}

pub fn project_rows(projects: &[Project]) -> Vec<Vec<String>> {
    projects
        .iter()
        .map(|p| {
            vec![
                p.name.clone(),
                p.environments
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                p.credential_count.to_string(),
                if p.archived {
                    "archived".to_owned()
                } else if p.password_locked && !p.unlocked {
                    "locked".to_owned()
                } else if p.password_locked {
                    "unlocked".to_owned()
                } else {
                    "-".to_owned()
                },
                p.description.clone(),
            ]
        })
        .collect()
}

pub fn print_project(project: &Project) {
    println!("Project:      {}", project.name);
    println!("Id:           {}", project.id);
    if !project.description.is_empty() {
        println!("Description:  {}", project.description);
    }
    println!(
        "Environments: {}",
        if project.environments.is_empty() {
            "(none)".to_owned()
        } else {
            project
                .environments
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!("Credentials:  {}", project.credential_count);
    println!(
        "Archived:     {}",
        if project.archived { "yes" } else { "no" }
    );
    println!(
        "Password:     {}",
        if !project.password_locked {
            "not set".to_owned()
        } else if project.unlocked {
            "set (unlocked this session)".to_owned()
        } else {
            "set (locked)".to_owned()
        }
    );
    if !project.repo_paths.is_empty() {
        println!("Repositories:");
        for repo in &project.repo_paths {
            println!("  - {repo}");
        }
    }
    if !project.notes.is_empty() {
        println!("Notes:        {}", project.notes);
    }
    println!("Created:      {}", project.created_at);
    println!("Updated:      {}", project.updated_at);
}

pub fn credential_rows(credentials: &[Credential]) -> Vec<Vec<String>> {
    credentials
        .iter()
        .map(|c| {
            vec![
                format!("{}/{}", c.project_name, c.name),
                c.provider.clone(),
                c.environment.to_string(),
                if c.is_reference {
                    format!("→ {}", c.linked_target.as_deref().unwrap_or("?"))
                } else {
                    c.masked_value.clone()
                },
                c.status.primary.to_string(),
            ]
        })
        .collect()
}

pub fn print_credential(c: &Credential) {
    println!("Credential:  {}/{}", c.project_name, c.name);
    println!("Id:          {}", c.id);
    println!("Provider:    {}", c.provider);
    println!("Environment: {}", c.environment);
    println!("Type:        {}", c.credential_type);
    if c.is_reference {
        println!(
            "Value:       reference to {}",
            c.linked_target.as_deref().unwrap_or("(missing)")
        );
    } else {
        println!("Value:       {} (masked)", c.masked_value);
    }
    println!("Status:      {}", c.status.primary);
    if let Some(v) = &c.key_created_at {
        println!("Key created: {v}");
    }
    if let Some(v) = &c.expires_at {
        println!("Expires:     {v}");
    }
    if let Some(v) = &c.last_validated_at {
        println!("Validated:   {v}");
    }
    if let Some(v) = &c.last_used_at {
        println!("Last used:   {v}");
    }
    if !c.docs_url.is_empty() {
        println!("Docs:        {}", c.docs_url);
    }
    if !c.notes.is_empty() {
        println!("Notes:       {}", c.notes);
    }
    println!("Added:       {}", c.created_at);
    println!("Updated:     {}", c.updated_at);
}

pub fn print_status_report(report: &StatusReport) {
    println!("Primary status: {}", report.primary);
    println!();
    for finding in &report.findings {
        println!("[{}] ({:?} confidence)", finding.status, finding.confidence);
        println!("  Reason:      {}", finding.reason);
        println!("  Source:      {}", finding.source);
        println!("  Observed:    {}", finding.observed_at);
        println!("  Recommended: {}", finding.recommended_action);
    }
}

pub fn print_provider(m: &ProviderManifest) {
    println!("Provider:     {} ({})", m.name, m.id);
    println!("Description:  {}", m.description);
    println!("Website:      {}", m.website);
    println!("API docs:     {}", m.api_docs_url);
    println!("Auth docs:    {}", m.auth_docs_url);
    println!("Manage keys:  {}", m.manage_url);
    if !m.env_vars.is_empty() {
        println!("Secret vars:  {}", m.env_vars.join(", "));
    }
    if !m.credential_types.is_empty() {
        println!("Key types:    {}", m.credential_types.join(", "));
    }
    if !m.expiration.is_empty() {
        println!("Expiration:   {}", m.expiration);
    }
    if !m.detection.is_empty() {
        println!("Detection patterns: {}", m.detection.len());
    }
    println!();
    print_capabilities(&m.capabilities);
}

pub fn print_capabilities(caps: &Capabilities) {
    let rows: Vec<Vec<String>> = caps
        .entries()
        .iter()
        .map(|(name, entry)| {
            let mut status = entry.support.label().to_string();
            if entry.requires_admin_credential {
                status.push_str(" · admin credential");
            }
            let attribution = entry.attribution.label();
            if attribution != "n/a" {
                status.push_str(&format!(" · {attribution}"));
            }
            vec![name.to_string(), status, entry.note.clone()]
        })
        .collect();
    table(&["CAPABILITY", "STATUS", "NOTE"], &rows);
}

pub fn print_permissions(p: &api_tracker_core::permissions::StoredPermissions) {
    println!(
        "Permissions (source: {}, confidence: {}):",
        p.source, p.confidence
    );
    println!("  Summary:   {}", p.normalized.summary);
    if !p.raw_scopes.is_empty() {
        println!("  Raw scopes: {}", p.raw_scopes.join(", "));
    }
    let show = |label: &str, list: &[String]| {
        if !list.is_empty() {
            println!("  {label}: {}", list.join(", "));
        }
    };
    show("Read      ", &p.normalized.read);
    show("Write     ", &p.normalized.write);
    show("Admin     ", &p.normalized.admin);
    show("Sensitive ", &p.normalized.sensitive);
    println!("  Synced:    {}", p.synced_at);
}

pub fn print_reuse_warnings(warnings: &[ReuseWarning]) {
    if warnings.is_empty() {
        return;
    }
    eprintln!();
    eprintln!("WARNING: credential reuse detected");
    for warning in warnings {
        eprintln!("  - [{}] {}", warning.kind, warning.message);
        eprintln!("    Recommendation: {}", warning.recommendation);
    }
    eprintln!();
}
