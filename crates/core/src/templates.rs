//! Project templates for common stacks.
//!
//! Templates are version-controlled TOML files under `templates/`, embedded
//! at compile time like provider manifests, so the catalog is always
//! available offline. A template carries suggested providers, environment
//! classifications, environment-variable NAMES with guidance, and
//! credential-separation / permission / rotation advice. **Templates never
//! contain credential values** — a validation test enforces that no
//! example or description matches any provider detection pattern.
//!
//! Applying a template creates (or annotates) a project and can render a
//! `.env.example` (names and comments only). It never creates credentials —
//! it prints the exact `key add` / `mapping set` commands instead, because
//! secret values only ever enter the vault through an explicit user action.

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};

/// One environment variable a stack conventionally uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateEnvVar {
    pub name: String,
    /// The provider this variable's credential comes from, when known.
    #[serde(default)]
    pub provider: Option<String>,
    /// Whether the value is a secret (drives vault vs plain-config advice).
    pub secret: bool,
    #[serde(default)]
    pub description: String,
}

/// A project template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub environments: Vec<String>,
    #[serde(default)]
    pub docs: Vec<String>,
    /// Suggested destination kinds (see `destinations::catalog`).
    #[serde(default)]
    pub destinations: Vec<String>,
    #[serde(default)]
    pub credential_separation: String,
    #[serde(default)]
    pub permission_guidance: String,
    #[serde(default)]
    pub rotation_guidance: String,
    #[serde(default, rename = "env")]
    pub env_vars: Vec<TemplateEnvVar>,
}

const TEMPLATE_SOURCES: &[(&str, &str)] = &[
    (
        "openai-app",
        include_str!("../../../templates/openai-app.toml"),
    ),
    (
        "anthropic-app",
        include_str!("../../../templates/anthropic-app.toml"),
    ),
    (
        "supabase-web",
        include_str!("../../../templates/supabase-web.toml"),
    ),
    (
        "stripe-app",
        include_str!("../../../templates/stripe-app.toml"),
    ),
    (
        "github-automation",
        include_str!("../../../templates/github-automation.toml"),
    ),
    (
        "nextjs-app",
        include_str!("../../../templates/nextjs-app.toml"),
    ),
    (
        "node-backend",
        include_str!("../../../templates/node-backend.toml"),
    ),
    (
        "python-backend",
        include_str!("../../../templates/python-backend.toml"),
    ),
    (
        "fullstack-saas",
        include_str!("../../../templates/fullstack-saas.toml"),
    ),
];

fn parse(source: &str) -> Result<Template> {
    let t: Template = toml::from_str(source)
        .map_err(|e| CoreError::InvalidInput(format!("template did not parse: {e}")))?;
    validate(&t)?;
    Ok(t)
}

fn validate(t: &Template) -> Result<()> {
    if t.id.is_empty() || t.id.to_lowercase() != t.id {
        return Err(CoreError::InvalidInput(format!(
            "template id '{}' must be non-empty lowercase",
            t.id
        )));
    }
    if t.name.is_empty() {
        return Err(CoreError::InvalidInput("template name is empty".into()));
    }
    for p in &t.providers {
        if crate::providers::find(p).is_none() {
            return Err(CoreError::InvalidInput(format!(
                "template '{}' references unknown provider '{p}'",
                t.id
            )));
        }
    }
    for e in &t.environments {
        e.parse::<crate::model::Environment>().map_err(|_| {
            CoreError::InvalidInput(format!(
                "template '{}' has an unknown environment '{e}'",
                t.id
            ))
        })?;
    }
    for v in &t.env_vars {
        let ok = !v.name.is_empty()
            && v.name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if !ok {
            return Err(CoreError::InvalidInput(format!(
                "template '{}' has an invalid env var name '{}'",
                t.id, v.name
            )));
        }
        if let Some(p) = &v.provider {
            if crate::providers::find(p).is_none() {
                return Err(CoreError::InvalidInput(format!(
                    "template '{}' env '{}' references unknown provider '{p}'",
                    t.id, v.name
                )));
            }
        }
    }
    Ok(())
}

/// The full validated template catalog.
pub fn catalog() -> Vec<Template> {
    TEMPLATE_SOURCES
        .iter()
        .map(|(id, src)| {
            let t = parse(src).unwrap_or_else(|e| panic!("embedded template '{id}' invalid: {e}"));
            assert_eq!(&t.id, id, "template id mismatch for '{id}'");
            t
        })
        .collect()
}

/// Find a template by id.
pub fn find(id: &str) -> Option<Template> {
    let id = id.to_lowercase();
    catalog().into_iter().find(|t| t.id == id)
}

/// Render a `.env.example` for a template: variable NAMES and comments
/// only, empty values. Never contains a secret.
pub fn render_env_example(t: &Template) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# .env.example for the '{}' template — variable names only, NO values.\n\
         # Copy to .env for local use, or prefer `api-tracker run` so secrets\n\
         # never land on disk. Generated by API Tracker; contains no secrets.\n\n",
        t.id
    ));
    for v in &t.env_vars {
        if !v.description.is_empty() {
            out.push_str(&format!("# {}\n", v.description));
        }
        if v.secret {
            out.push_str("# SECRET — store in the API Tracker vault, do not commit a value.\n");
        }
        out.push_str(&format!("{}=\n\n", v.name));
    }
    out
}

/// The follow-up commands that finish the workflow (credentials are only
/// ever added explicitly, so applying a template prints these instead of
/// inventing records).
pub fn next_steps(t: &Template, project: &str) -> Vec<String> {
    let mut steps = Vec::new();
    for v in t.env_vars.iter().filter(|v| v.secret) {
        let provider = v.provider.clone().unwrap_or_else(|| "other".into());
        let key_name = v.name.to_lowercase().replace('_', "-");
        steps.push(format!(
            "api-tracker key add --project {project} --name {key_name} --provider {provider}"
        ));
        steps.push(format!(
            "api-tracker mapping set --project {project} {project}/{key_name} {}",
            v.name
        ));
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_embedded_templates_parse_and_validate() {
        let all = catalog();
        assert_eq!(all.len(), 9);
        let mut ids: Vec<&str> = all.iter().map(|t| t.id.as_str()).collect();
        ids.sort();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids, deduped, "duplicate template ids");
    }

    #[test]
    fn templates_never_contain_values_matching_detection_patterns() {
        // No template text (descriptions, guidance, examples) may match any
        // provider detection regex — that would mean a template ships
        // something shaped like a real secret.
        let manifests = crate::providers::manifests();
        for t in catalog() {
            let blob = toml::to_string(&t).unwrap();
            for m in manifests {
                for d in &m.detection {
                    let re = regex::Regex::new(&d.regex).unwrap();
                    assert!(
                        !re.is_match(&blob),
                        "template '{}' contains text matching detection '{}'",
                        t.id,
                        d.name
                    );
                }
            }
        }
    }

    #[test]
    fn env_example_contains_names_and_no_values() {
        let t = find("fullstack-saas").unwrap();
        let example = render_env_example(&t);
        assert!(example.contains("STRIPE_SECRET_KEY=\n"));
        assert!(example.contains("SECRET — store in the API Tracker vault"));
        // Every assignment is empty.
        for line in example.lines() {
            if let Some((_, v)) = line.split_once('=') {
                if !line.starts_with('#') {
                    assert!(v.is_empty(), "example line has a value: {line}");
                }
            }
        }
    }

    #[test]
    fn next_steps_cover_secret_vars_only() {
        let t = find("supabase-web").unwrap();
        let steps = next_steps(&t, "my-app");
        assert!(steps.iter().any(|s| s.contains("supabase-secret-key")));
        assert!(!steps.iter().any(|s| s.contains("SUPABASE_URL")));
    }
}
