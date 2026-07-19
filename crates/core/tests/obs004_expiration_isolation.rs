//! OBS-004 regression: one credential's malformed provider expiration must
//! not break listings, details, alerts, or the monitor for UNRELATED
//! credentials. The malformed value is shown as invalid — never a
//! fabricated date — and status/alerts fail locally to that credential.
//!
//! Provider `provider_expires_at` is written verbatim from provider sync
//! with no parse check, so a hostile/buggy provider can poison a row. We
//! simulate that by writing the malformed value directly (exactly the state
//! that sync leaves) and asserting the rest of the vault keeps working.

mod common;

use api_tracker_core::model::Environment;
use common::{add_key, add_project, new_vault, FAKE_KEY_1, FAKE_KEY_2};

/// Poison a credential's provider_expires_at the way a malformed provider
/// sync response would (the write path stores it verbatim).
fn set_provider_expiry(vault: &api_tracker_core::vault::UnlockedVault, cred_id: &str, raw: &str) {
    vault
        .connection()
        .execute(
            "UPDATE credentials SET provider_expires_at = ?1 WHERE id = ?2",
            rusqlite::params![raw, cred_id],
        )
        .expect("poison provider_expires_at");
}

#[test]
fn one_malformed_expiration_does_not_break_the_whole_listing() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (good, _) = add_key(
        &mut vault,
        "app",
        "good",
        FAKE_KEY_1,
        Environment::Production,
    );
    let (bad, _) = add_key(
        &mut vault,
        "app",
        "bad",
        FAKE_KEY_2,
        Environment::Production,
    );

    // Each of these malformed provider values, in isolation, previously
    // failed EVERY credential listing vault-wide (OBS-004).
    for raw in [
        "not-a-date",
        "", // note: empty is normalized to None, not invalid
        "2026-13-45T99:99:99Z",
        "9999999999999999-01-01T00:00:00Z",
        "١٤٤٥", // non-ASCII digits
    ] {
        set_provider_expiry(&vault, &bad.id, raw);

        // The whole-vault listing still succeeds and includes BOTH creds.
        let all = vault
            .list_credentials(None)
            .expect("a malformed value must not fail the listing");
        assert_eq!(
            all.len(),
            2,
            "both credentials must be listed (raw={raw:?})"
        );

        let good_model = all.iter().find(|c| c.id == good.id).unwrap();
        assert!(
            !good_model.provider_expires_at_invalid,
            "the unrelated credential must be unaffected"
        );

        let bad_model = all.iter().find(|c| c.id == bad.id).unwrap();
        if raw.is_empty() {
            assert!(
                !bad_model.provider_expires_at_invalid,
                "an empty value is 'not reported', not invalid"
            );
        } else {
            assert!(
                bad_model.provider_expires_at_invalid,
                "the malformed value must be flagged invalid (raw={raw:?})"
            );
            // The raw string is preserved for diagnostics, verbatim.
            assert_eq!(bad_model.provider_expires_at.as_deref(), Some(raw));
            // No date was fabricated: status must not be Expired/ExpiringSoon
            // purely from an unparseable value.
            assert_ne!(
                bad_model.status.primary.as_str(),
                "expired",
                "an unparseable value must never fabricate 'expired'"
            );
            // The status carries an explicit unknown finding about it.
            assert!(
                bad_model
                    .status
                    .findings
                    .iter()
                    .any(|f| f.reason.contains("could not be parsed")),
                "status must explain the unparseable expiration"
            );
        }
    }
}

#[test]
fn detail_view_and_edits_of_unrelated_credentials_still_work() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (good, _) = add_key(
        &mut vault,
        "app",
        "good",
        FAKE_KEY_1,
        Environment::Production,
    );
    let (bad, _) = add_key(
        &mut vault,
        "app",
        "bad",
        FAKE_KEY_2,
        Environment::Production,
    );
    set_provider_expiry(&vault, &bad.id, "totally-broken");

    // The unrelated credential's detail view works.
    let good_detail = vault
        .get_credential(&good.id)
        .expect("unrelated detail works");
    assert!(!good_detail.provider_expires_at_invalid);

    // The poisoned credential's OWN detail also works (shown invalid, not an
    // error) — otherwise you could never inspect or fix it.
    let bad_detail = vault
        .get_credential(&bad.id)
        .expect("poisoned detail works");
    assert!(bad_detail.provider_expires_at_invalid);
}

#[test]
fn a_later_valid_sync_clears_the_invalid_flag() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(&mut vault, "app", "k", FAKE_KEY_1, Environment::Production);
    set_provider_expiry(&vault, &cred.id, "garbage");
    assert!(
        vault
            .get_credential(&cred.id)
            .unwrap()
            .provider_expires_at_invalid
    );

    // A subsequent valid provider value (what a good sync would write)
    // clears the invalid state, and no unparseable-expiration finding
    // remains.
    set_provider_expiry(&vault, &cred.id, "2030-01-01T00:00:00Z");
    let refreshed = vault.get_credential(&cred.id).unwrap();
    assert!(!refreshed.provider_expires_at_invalid);
    assert!(
        !refreshed
            .status
            .findings
            .iter()
            .any(|f| f.reason.contains("could not be parsed")),
        "the unparseable-expiration finding must be gone after a valid sync"
    );
    assert_ne!(
        refreshed.status.primary.as_str(),
        "expiring soon",
        "a far-future valid expiry is not expiring soon"
    );
}

#[test]
fn monitor_run_survives_a_malformed_expiration() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (_good, _) = add_key(
        &mut vault,
        "app",
        "good",
        FAKE_KEY_1,
        Environment::Production,
    );
    let (bad, _) = add_key(
        &mut vault,
        "app",
        "bad",
        FAKE_KEY_2,
        Environment::Production,
    );
    set_provider_expiry(&vault, &bad.id, "not-a-timestamp");

    // The monitor lists all credentials internally; one bad value must not
    // abort the entire local alert pass.
    let summary = vault
        .run_monitor()
        .expect("the monitor must not fail on a malformed expiration");
    // Every credential was considered (no early abort).
    assert!(summary.checked >= 2, "all credentials must be checked");
}

#[test]
fn expires_at_column_is_also_isolated() {
    // The user-entered expires_at is validated on write, but a corrupted DB
    // (or a future write path) could still store garbage; that too must be
    // isolated rather than failing the listing.
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(&mut vault, "app", "k", FAKE_KEY_1, Environment::Production);
    vault
        .connection()
        .execute(
            "UPDATE credentials SET expires_at = 'broken' WHERE id = ?1",
            [&cred.id],
        )
        .unwrap();
    let model = vault.get_credential(&cred.id).expect("listing survives");
    assert!(model.expires_at_invalid);
    assert_eq!(model.expires_at.as_deref(), Some("broken"));
}
