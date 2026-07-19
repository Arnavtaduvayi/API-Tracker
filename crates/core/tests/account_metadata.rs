//! Provider-account metadata: only provider-reported identity from
//! official endpoints is stored, with source and sync time. Nothing is
//! derived from credential appearance, and providers without an identity
//! endpoint are reported unsupported instead of guessed.

mod common;

use api_tracker_core::http::MockHttpClient;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::AddCredential;
use common::*;

fn add_cred(
    vault: &mut api_tracker_core::vault::UnlockedVault,
    project: &str,
    provider: &str,
    name: &str,
    value: &str,
) {
    vault
        .add_credential(AddCredential {
            project: project.into(),
            provider: provider.into(),
            name: name.into(),
            environment: Environment::Production,
            value: SecretString::from(value),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
}

#[test]
fn github_account_sync_stores_provider_reported_identity() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");
    add_cred(
        &mut vault,
        "web",
        "github",
        "gh",
        "ghp_FAKE0000000000000000000000000000000000",
    );
    vault.provider_connect("github", "web/gh").unwrap();

    let mock = MockHttpClient::json(
        r#"{"login":"octocat","id":583231,"email":"octo@example.com",
            "company":"GitHub","plan":{"name":"pro","space":976562499,"private_repos":9999}}"#,
    );
    let info = vault.provider_account_sync("github", &mock).unwrap();
    assert_eq!(info.name.as_deref(), Some("octocat"));
    assert_eq!(info.plan.as_deref(), Some("pro"));

    let status = vault.provider_connection_status("github").unwrap();
    assert_eq!(status.account_name.as_deref(), Some("octocat"));
    assert_eq!(status.account_email.as_deref(), Some("octo@example.com"));
    assert_eq!(status.account_id.as_deref(), Some("583231"));
    assert_eq!(status.account_plan.as_deref(), Some("pro"));
    assert_eq!(status.account_source.as_deref(), Some("GitHub GET /user"));
    assert!(status.account_synced_at.is_some());
}

#[test]
fn stripe_account_sync_reads_v1_account() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "shop");
    add_cred(
        &mut vault,
        "shop",
        "stripe",
        "sk",
        "sk_test_FAKE000000000000000000000000",
    );
    vault.provider_connect("stripe", "shop/sk").unwrap();

    let mock = MockHttpClient::json(
        r#"{"id":"acct_1FAKE","email":"owner@example.com",
            "business_profile":{"name":"Example Shop"},"country":"US"}"#,
    );
    let info = vault.provider_account_sync("stripe", &mock).unwrap();
    assert_eq!(info.account_id.as_deref(), Some("acct_1FAKE"));
    assert_eq!(info.name.as_deref(), Some("Example Shop"));
    assert_eq!(info.plan, None);
    let status = vault.provider_connection_status("stripe").unwrap();
    assert_eq!(status.account_email.as_deref(), Some("owner@example.com"));
}

#[test]
fn supabase_multiple_orgs_never_guesses_one() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    add_cred(
        &mut vault,
        "app",
        "supabase",
        "pat",
        "sbp_FAKE0000000000000000000000000000000000000000",
    );
    vault.provider_connect("supabase", "app/pat").unwrap();

    // One org: id + name stored.
    let one = MockHttpClient::json(r#"[{"id":"org_abc","name":"My Org"}]"#);
    let info = vault.provider_account_sync("supabase", &one).unwrap();
    assert_eq!(info.account_id.as_deref(), Some("org_abc"));
    assert_eq!(info.name.as_deref(), Some("My Org"));

    // Several orgs: no id is claimed; the count is reported honestly.
    let many = MockHttpClient::json(r#"[{"id":"org_a","name":"A"},{"id":"org_b","name":"B"}]"#);
    let info = vault.provider_account_sync("supabase", &many).unwrap();
    assert_eq!(info.account_id, None);
    assert_eq!(info.name.as_deref(), Some("2 organizations visible"));
}

#[test]
fn openai_account_sync_is_honestly_unsupported() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "ai");
    add_cred(
        &mut vault,
        "ai",
        "openai",
        "admin",
        "sk-FAKE00000000000000000000000000000000",
    );
    vault.provider_connect("openai", "ai/admin").unwrap();
    let mock = MockHttpClient::json("{}");
    let err = vault.provider_account_sync("openai", &mock).unwrap_err();
    assert!(err.to_string().contains("no documented account-identity"));
    // Nothing was stored.
    let status = vault.provider_connection_status("openai").unwrap();
    assert!(status.account_synced_at.is_none());
}

#[test]
fn anthropic_account_sync_uses_organizations_me() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "ai");
    add_cred(
        &mut vault,
        "ai",
        "anthropic",
        "admin",
        "sk-ant-admin01-FAKE0000000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    vault.provider_connect("anthropic", "ai/admin").unwrap();
    let mock = MockHttpClient::json(
        r#"{"id":"3c9f2e6a-0000-0000-0000-000000000000","type":"organization","name":"Example Org"}"#,
    );
    let info = vault.provider_account_sync("anthropic", &mock).unwrap();
    assert_eq!(info.name.as_deref(), Some("Example Org"));
    assert!(info.account_id.is_some());
    assert!(info.source.contains("/v1/organizations/me"));
}

#[test]
fn account_sync_without_connection_is_rejected() {
    let (_dir, _paths, vault) = new_vault();
    let mock = MockHttpClient::json("{}");
    assert!(vault.provider_account_sync("github", &mock).is_err());
}
