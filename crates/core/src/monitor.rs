//! Local monitoring rules: turn the evidence the vault already holds into
//! explainable alerts.
//!
//! These functions are pure — they map a credential's evaluated status (and
//! reuse classification) to zero or more [`NewAlert`]s with a stable
//! `dedup_key`. The vault owns orchestration ([`crate::vault::UnlockedVault::run_monitor`]):
//! it gathers credentials, calls these rules, upserts the alerts, and
//! auto-resolves conditions that no longer hold. Nothing here performs I/O.

use crate::alerts::{AlertKind, NewAlert, Severity};
use crate::model::Credential;
use crate::providers::Confidence;
use crate::reuse::{ReuseKind, ReuseWarning};
use crate::status::Status;

fn dedup(kind: &str, credential_id: &str) -> String {
    format!("{kind}:{credential_id}")
}

fn label(cred: &Credential) -> String {
    format!("{}/{}", cred.project_name, cred.name)
}

/// Alerts derived from a credential's evaluated status. One credential can
/// raise several (e.g. expired *and* possibly exposed).
pub fn credential_alerts(cred: &Credential, observed_at: &str) -> Vec<NewAlert> {
    let mut out = Vec::new();
    let name = label(cred);

    for finding in &cred.status.findings {
        let alert = match finding.status {
            Status::Expired => Some((
                AlertKind::Expired,
                Severity::High,
                format!("Credential '{name}' has expired"),
            )),
            Status::ExpiringSoon => Some((
                AlertKind::ExpiringSoon,
                Severity::Medium,
                format!("Credential '{name}' is expiring soon"),
            )),
            Status::Stale => Some((
                AlertKind::Stale,
                Severity::Low,
                format!("Credential '{name}' looks stale"),
            )),
            Status::Unused => Some((
                AlertKind::Unused,
                Severity::Low,
                format!("Credential '{name}' appears unused"),
            )),
            Status::PossiblyExposed => Some((
                AlertKind::PossibleExposure,
                Severity::Critical,
                format!("Credential '{name}' may be exposed"),
            )),
            _ => None,
        };
        if let Some((kind, severity, title)) = alert {
            out.push(NewAlert {
                kind,
                severity,
                dedup_key: dedup(kind.as_str(), &cred.id),
                title,
                detail: finding.reason.clone(),
                evidence: format!(
                    "source: {}; observed: {}",
                    finding.source, finding.observed_at
                ),
                confidence: finding_confidence(finding.confidence),
                recommended_action: finding.recommended_action.clone(),
                project_id: Some(cred.project_id.clone()),
                credential_id: Some(cred.id.clone()),
                observed_at: observed_at.to_string(),
            });
        }
    }
    out
}

fn finding_confidence(c: crate::status::Confidence) -> Confidence {
    match c {
        crate::status::Confidence::High => Confidence::High,
        crate::status::Confidence::Medium => Confidence::Medium,
        crate::status::Confidence::Low => Confidence::Low,
    }
}

/// Alerts derived from reuse warnings for a credential.
pub fn reuse_alerts(
    cred: &Credential,
    warnings: &[ReuseWarning],
    observed_at: &str,
) -> Vec<NewAlert> {
    let name = label(cred);
    let mut out = Vec::new();
    // Production-shared-with-development is the highest-signal case.
    if let Some(w) = warnings
        .iter()
        .find(|w| w.kind == ReuseKind::ProductionSharedWithDevelopment)
    {
        out.push(NewAlert {
            kind: AlertKind::ProductionInDevelopment,
            severity: Severity::High,
            dedup_key: dedup("production_in_development", &cred.id),
            title: format!("Production credential '{name}' is shared with development"),
            detail: w.message.clone(),
            evidence: format!("reuse type: {}", w.kind),
            confidence: Confidence::High,
            recommended_action: w.recommendation.clone(),
            project_id: Some(cred.project_id.clone()),
            credential_id: Some(cred.id.clone()),
            observed_at: observed_at.to_string(),
        });
    } else if warnings.iter().any(|w| w.kind == ReuseKind::AcrossProjects) {
        let others: Vec<String> = warnings
            .iter()
            .filter(|w| w.kind == ReuseKind::AcrossProjects)
            .map(|w| w.other.project_name.clone())
            .collect();
        out.push(NewAlert {
            kind: AlertKind::ReusedAcrossProjects,
            severity: Severity::Medium,
            dedup_key: dedup("reused_across_projects", &cred.id),
            title: format!("Credential '{name}' is reused across projects"),
            detail: format!("the same secret is stored in: {}", others.join(", ")),
            evidence: "keyed fingerprint comparison inside this vault".into(),
            confidence: Confidence::High,
            recommended_action:
                "create a separate provider credential per project, or reference one entry".into(),
            project_id: Some(cred.project_id.clone()),
            credential_id: Some(cred.id.clone()),
            observed_at: observed_at.to_string(),
        });
    }
    out
}

/// The alert kinds this monitor manages, for auto-resolution.
pub fn managed_credential_kinds() -> Vec<AlertKind> {
    vec![
        AlertKind::Expired,
        AlertKind::ExpiringSoon,
        AlertKind::Stale,
        AlertKind::Unused,
        AlertKind::PossibleExposure,
        AlertKind::ProductionInDevelopment,
        AlertKind::ReusedAcrossProjects,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Environment;
    use crate::status::{Confidence as SConf, Finding, StatusReport};

    fn cred_with(status: Status, reason: &str) -> Credential {
        Credential {
            id: "cred-1".into(),
            project_id: "proj-1".into(),
            project_name: "web".into(),
            provider: "openai".into(),
            name: "key".into(),
            environment: Environment::Production,
            credential_type: "api_key".into(),
            masked_value: "sk-…01".into(),
            is_reference: false,
            linked_credential_id: None,
            linked_target: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            key_created_at: None,
            expires_at: None,
            last_validated_at: None,
            last_used_at: None,
            docs_url: String::new(),
            notes: String::new(),
            manually_disabled: false,
            revoked: false,
            marked_invalid: false,
            possibly_exposed: false,
            exposure_note: String::new(),
            status: StatusReport {
                primary: status,
                findings: vec![Finding {
                    status,
                    reason: reason.into(),
                    source: "test".into(),
                    observed_at: "2026-07-18T00:00:00Z".into(),
                    confidence: SConf::High,
                    recommended_action: "act".into(),
                }],
            },
        }
    }

    #[test]
    fn expired_credential_yields_high_alert() {
        let cred = cred_with(Status::Expired, "the date passed");
        let alerts = credential_alerts(&cred, "2026-07-18T00:00:00Z");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::Expired);
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].dedup_key, "expired:cred-1");
        assert_eq!(alerts[0].credential_id.as_deref(), Some("cred-1"));
    }

    #[test]
    fn exposed_credential_is_critical() {
        let cred = cred_with(Status::PossiblyExposed, "found in a repo");
        let alerts = credential_alerts(&cred, "now");
        assert_eq!(alerts[0].kind, AlertKind::PossibleExposure);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn healthy_credential_yields_no_alerts() {
        let cred = cred_with(Status::Active, "recently used");
        assert!(credential_alerts(&cred, "now").is_empty());
    }
}
