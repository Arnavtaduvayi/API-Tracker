//! Explainable credential status engine.
//!
//! Statuses are only assigned when there is concrete evidence. Every finding
//! records its reason, evidence source, observation time, confidence, and a
//! recommended action. In this milestone all evidence is local (user-entered
//! dates, manual validation/usage marks, and vault reuse analysis); provider
//! integrations will add stronger evidence sources later.

use crate::model::Environment;
use crate::settings::VaultSettings;
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Unknown,
    Active,
    Invalid,
    Expired,
    ExpiringSoon,
    Unused,
    Stale,
    SharedAcrossProjects,
    PossiblyExposed,
    ManuallyDisabled,
    Revoked,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Unknown => "unknown",
            Status::Active => "active",
            Status::Invalid => "invalid",
            Status::Expired => "expired",
            Status::ExpiringSoon => "expiring soon",
            Status::Unused => "unused",
            Status::Stale => "stale",
            Status::SharedAcrossProjects => "shared across projects",
            Status::PossiblyExposed => "possibly exposed",
            Status::ManuallyDisabled => "manually disabled",
            Status::Revoked => "revoked",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// One piece of evidence-backed classification.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub status: Status,
    pub reason: String,
    pub source: String,
    pub observed_at: String,
    pub confidence: Confidence,
    pub recommended_action: String,
}

/// The overall classification: one primary status plus all findings.
#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    pub primary: Status,
    pub findings: Vec<Finding>,
}

/// Evidence inputs for one credential.
#[derive(Debug, Clone)]
pub struct StatusInputs<'a> {
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub last_validated_at: Option<OffsetDateTime>,
    pub last_used_at: Option<OffsetDateTime>,
    pub manually_disabled: bool,
    pub revoked: bool,
    pub marked_invalid: bool,
    pub possibly_exposed: bool,
    pub exposure_note: &'a str,
    /// Names of *other* projects that hold a credential with the same
    /// fingerprint (copies or references).
    pub shared_with_projects: &'a [String],
    /// True when the sharing includes an intentional reference record.
    pub sharing_is_reference: bool,
    pub environment: Environment,
}

/// Primary-status precedence, most severe first.
const PRECEDENCE: [Status; 11] = [
    Status::Revoked,
    Status::ManuallyDisabled,
    Status::Expired,
    Status::Invalid,
    Status::PossiblyExposed,
    Status::ExpiringSoon,
    Status::SharedAcrossProjects,
    Status::Stale,
    Status::Unused,
    Status::Active,
    Status::Unknown,
];

pub fn evaluate(
    inputs: &StatusInputs<'_>,
    settings: &VaultSettings,
    now: OffsetDateTime,
) -> StatusReport {
    let mut findings: Vec<Finding> = Vec::new();
    let observed = crate::clock::to_rfc3339(now);
    let manual_source = "manual flag set by the user";
    let timestamp_source = "vault timestamps (manually recorded in this milestone)";

    if inputs.revoked {
        findings.push(Finding {
            status: Status::Revoked,
            reason: "the credential was marked as revoked".into(),
            source: manual_source.into(),
            observed_at: observed.clone(),
            confidence: Confidence::High,
            recommended_action: "remove this record once no project needs its history".into(),
        });
    }
    if inputs.manually_disabled {
        findings.push(Finding {
            status: Status::ManuallyDisabled,
            reason: "the credential was manually disabled in API Tracker".into(),
            source: manual_source.into(),
            observed_at: observed.clone(),
            confidence: Confidence::High,
            recommended_action:
                "re-enable it when it is needed again, or revoke it at the provider".into(),
        });
    }
    if let Some(expires) = inputs.expires_at {
        if expires <= now {
            findings.push(Finding {
                status: Status::Expired,
                reason: format!(
                    "the user-entered expiration date {} has passed",
                    crate::clock::to_rfc3339(expires)
                ),
                source: "user-entered expiration date".into(),
                observed_at: observed.clone(),
                confidence: Confidence::High,
                recommended_action: "create a replacement credential at the provider and rotate"
                    .into(),
            });
        } else {
            let window = time::Duration::days(i64::from(settings.expiring_soon_days));
            if expires - now <= window {
                let days_left = (expires - now).whole_days().max(0);
                findings.push(Finding {
                    status: Status::ExpiringSoon,
                    reason: format!(
                        "the user-entered expiration date is about {days_left} day(s) away (threshold: {} days)",
                        settings.expiring_soon_days
                    ),
                    source: "user-entered expiration date".into(),
                    observed_at: observed.clone(),
                    confidence: Confidence::High,
                    recommended_action: "rotate the credential before it expires".into(),
                });
            }
        }
    }
    if inputs.marked_invalid {
        findings.push(Finding {
            status: Status::Invalid,
            reason: "the last recorded validation marked this credential as not working".into(),
            source: manual_source.into(),
            observed_at: observed.clone(),
            confidence: Confidence::Medium,
            recommended_action:
                "verify at the provider; replace the stored value if it was rotated".into(),
        });
    }
    if inputs.possibly_exposed {
        let mut reason = "the credential was flagged as possibly exposed".to_owned();
        if !inputs.exposure_note.is_empty() {
            reason.push_str(&format!(" ({})", inputs.exposure_note));
        }
        findings.push(Finding {
            status: Status::PossiblyExposed,
            reason,
            source: manual_source.into(),
            observed_at: observed.clone(),
            confidence: Confidence::Medium,
            recommended_action: "rotate the credential at the provider as soon as possible".into(),
        });
    }
    if !inputs.shared_with_projects.is_empty() {
        let projects = inputs.shared_with_projects.join(", ");
        let (reason, confidence) = if inputs.sharing_is_reference {
            (
                format!(
                    "the same secret value is intentionally referenced by project(s): {projects}"
                ),
                Confidence::High,
            )
        } else {
            (
                format!("an identical secret value is stored separately in project(s): {projects}"),
                Confidence::High,
            )
        };
        findings.push(Finding {
            status: Status::SharedAcrossProjects,
            reason,
            source: "keyed fingerprint comparison inside this vault".into(),
            observed_at: observed.clone(),
            confidence,
            recommended_action: if inputs.sharing_is_reference {
                "intentional sharing; consider separate provider credentials if these projects have different risk levels".into()
            } else {
                "create separate provider credentials per project, or keep one entry and reference it".into()
            },
        });
    }

    // A failed validation (marked_invalid) is recorded in last_validated_at
    // but is NOT evidence that the credential works, so it must not count as
    // fresh activity — otherwise it would produce a contradictory
    // "active, no action needed" finding alongside the "invalid" one.
    let validation_activity = if inputs.marked_invalid {
        None
    } else {
        inputs.last_validated_at
    };
    let freshest_activity = match (inputs.last_used_at, validation_activity) {
        (Some(u), Some(v)) => Some(u.max(v)),
        (Some(u), None) => Some(u),
        (None, Some(v)) => Some(v),
        (None, None) => None,
    };
    match freshest_activity {
        Some(fresh) => {
            let stale_window = time::Duration::days(i64::from(settings.stale_days));
            if now - fresh >= stale_window {
                findings.push(Finding {
                    status: Status::Stale,
                    reason: format!(
                        "the last recorded use or validation was on {} (threshold: {} days)",
                        crate::clock::to_rfc3339(fresh),
                        settings.stale_days
                    ),
                    source: timestamp_source.into(),
                    observed_at: observed.clone(),
                    confidence: Confidence::Low,
                    recommended_action:
                        "confirm the credential is still needed; revoke it at the provider if not"
                            .into(),
                });
            } else {
                findings.push(Finding {
                    status: Status::Active,
                    reason: format!(
                        "use or validation was recorded on {}",
                        crate::clock::to_rfc3339(fresh)
                    ),
                    source: timestamp_source.into(),
                    confidence: Confidence::Medium,
                    observed_at: observed.clone(),
                    recommended_action: "no action needed".into(),
                });
            }
        }
        None => {
            let unused_window = time::Duration::days(i64::from(settings.unused_days));
            if now - inputs.created_at >= unused_window {
                findings.push(Finding {
                    status: Status::Unused,
                    reason: format!(
                        "no use or validation has been recorded in the {} day(s) since this record was added",
                        settings.unused_days
                    ),
                    source: timestamp_source.into(),
                    observed_at: observed.clone(),
                    confidence: Confidence::Low,
                    recommended_action:
                        "if the credential is genuinely unused, revoke it at the provider".into(),
                });
            }
        }
    }

    let primary = PRECEDENCE
        .iter()
        .find(|s| findings.iter().any(|f| f.status == **s))
        .copied()
        .unwrap_or(Status::Unknown);

    if findings.is_empty() {
        findings.push(Finding {
            status: Status::Unknown,
            reason: "no validation, usage, expiration, or exposure evidence has been recorded"
                .into(),
            source: "absence of local evidence".into(),
            observed_at: observed,
            confidence: Confidence::High,
            recommended_action:
                "record a validation or usage event, or add expiration metadata, to improve tracking"
                    .into(),
        });
    }

    StatusReport { primary, findings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::now;

    fn base_inputs() -> StatusInputs<'static> {
        StatusInputs {
            created_at: now(),
            expires_at: None,
            last_validated_at: None,
            last_used_at: None,
            manually_disabled: false,
            revoked: false,
            marked_invalid: false,
            possibly_exposed: false,
            exposure_note: "",
            shared_with_projects: &[],
            sharing_is_reference: false,
            environment: Environment::Development,
        }
    }

    fn settings() -> VaultSettings {
        VaultSettings::default()
    }

    #[test]
    fn fresh_credential_is_unknown_with_explanation() {
        let report = evaluate(&base_inputs(), &settings(), now());
        assert_eq!(report.primary, Status::Unknown);
        assert_eq!(report.findings.len(), 1);
        assert!(!report.findings[0].reason.is_empty());
    }

    #[test]
    fn expired_takes_precedence_over_stale() {
        let t = now();
        let mut inputs = base_inputs();
        inputs.created_at = t - time::Duration::days(400);
        inputs.expires_at = Some(t - time::Duration::days(1));
        inputs.last_used_at = Some(t - time::Duration::days(200));
        let report = evaluate(&inputs, &settings(), t);
        assert_eq!(report.primary, Status::Expired);
        assert!(report.findings.iter().any(|f| f.status == Status::Stale));
    }

    #[test]
    fn expiring_soon_within_threshold() {
        let t = now();
        let mut inputs = base_inputs();
        inputs.expires_at = Some(t + time::Duration::days(5));
        let report = evaluate(&inputs, &settings(), t);
        assert_eq!(report.primary, Status::ExpiringSoon);
        assert!(report.findings[0].reason.contains("day"));
    }

    #[test]
    fn future_expiry_beyond_threshold_is_not_flagged() {
        let t = now();
        let mut inputs = base_inputs();
        inputs.expires_at = Some(t + time::Duration::days(60));
        let report = evaluate(&inputs, &settings(), t);
        assert_eq!(report.primary, Status::Unknown);
    }

    #[test]
    fn recent_validation_is_active() {
        let t = now();
        let mut inputs = base_inputs();
        inputs.last_validated_at = Some(t - time::Duration::days(2));
        let report = evaluate(&inputs, &settings(), t);
        assert_eq!(report.primary, Status::Active);
    }

    #[test]
    fn old_activity_is_stale() {
        let t = now();
        let mut inputs = base_inputs();
        inputs.created_at = t - time::Duration::days(200);
        inputs.last_used_at = Some(t - time::Duration::days(120));
        let report = evaluate(&inputs, &settings(), t);
        assert_eq!(report.primary, Status::Stale);
    }

    #[test]
    fn never_used_old_credential_is_unused() {
        let t = now();
        let mut inputs = base_inputs();
        inputs.created_at = t - time::Duration::days(45);
        let report = evaluate(&inputs, &settings(), t);
        assert_eq!(report.primary, Status::Unused);
    }

    #[test]
    fn revoked_beats_everything() {
        let t = now();
        let mut inputs = base_inputs();
        inputs.revoked = true;
        inputs.manually_disabled = true;
        inputs.expires_at = Some(t - time::Duration::days(1));
        inputs.possibly_exposed = true;
        let report = evaluate(&inputs, &settings(), t);
        assert_eq!(report.primary, Status::Revoked);
        assert!(report.findings.len() >= 4);
    }

    #[test]
    fn shared_across_projects_reported_with_project_names() {
        let t = now();
        let shared = vec!["other-project".to_owned()];
        let mut inputs = base_inputs();
        inputs.shared_with_projects = &shared;
        let report = evaluate(&inputs, &settings(), t);
        assert_eq!(report.primary, Status::SharedAcrossProjects);
        assert!(report.findings[0].reason.contains("other-project"));
    }

    #[test]
    fn every_finding_has_reason_source_confidence_action() {
        let t = now();
        let shared = vec!["p2".to_owned()];
        let mut inputs = base_inputs();
        inputs.revoked = true;
        inputs.manually_disabled = true;
        inputs.marked_invalid = true;
        inputs.possibly_exposed = true;
        inputs.expires_at = Some(t + time::Duration::days(3));
        inputs.last_used_at = Some(t - time::Duration::days(1));
        inputs.shared_with_projects = &shared;
        let report = evaluate(&inputs, &settings(), t);
        for finding in &report.findings {
            assert!(!finding.reason.is_empty());
            assert!(!finding.source.is_empty());
            assert!(!finding.observed_at.is_empty());
            assert!(!finding.recommended_action.is_empty());
        }
    }
}
