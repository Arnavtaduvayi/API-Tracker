# Consent-first product analytics

Tethra uses the GA4 web stream `G-MJQHJ6JT5Z` in Firebase project
`usetethra`. Analytics is **off by default** on the landing site and desktop
app. Google code is not requested until a user affirmatively allows analytics.
Core product behavior never depends on consent.

This is pseudonymous measurement, not authentication and not guaranteed
anonymous under every privacy law. Tethra has no Firebase Authentication user
and sends no GA `user_id`. GA's first-party client identifier is the only
returning-user mechanism after opt-in.

## Consent behavior

- Landing choice: local storage key `tethra.analytics-consent.v1`; change it
  with **Privacy choices** in the footer.
- Desktop choice: the same key in the Tauri webview's separate local storage;
  change it under **Settings -> Pseudonymous product analytics**.
- Before grant: no `gtag.js`, no GA request, no Analytics cookie.
- After grant: `analytics_storage=granted`; `ad_storage`, `ad_user_data`, and
  `ad_personalization` remain denied.
- Google Signals and ad personalization signals are disabled.
- On withdrawal: events stop, GA is disabled, consent is updated to denied,
  and accessible `_ga` cookies are cleared.
- Landing collection runs only on the HTTPS production hosts, never from
  `file://`, localhost, or a developer preview.

## Landing events

| Event | When it fires | Parameters |
| --- | --- | --- |
| `landing_session_start` | A consented page initializes | `page_type` |
| `landing_section_view` | A home-page section reaches 45% visibility, once per page | `page_type`, `section` |
| `dmg_download_clicked` | A DMG CTA is clicked | `page_type`, `source` (`nav`, `hero`, `final`, `legal`) |
| `navigation_clicked` | An instrumented navigation link is clicked | `page_type`, `destination` |
| `legal_document_opened` | Privacy or Terms link is clicked | `page_type`, `document` |
| `analytics_consent_granted` | The user selects Allow | `page_type`, fixed consent-banner source |

Website locations are normalized to `https://usetethra.com/`, `/privacy`, or
`/terms`, and referrers are suppressed in Tethra's GA configuration.

## Desktop events

| Event | When it fires | Parameters |
| --- | --- | --- |
| `app_session_start` | A consented app webview session initializes | `app_surface=desktop` |
| `screen_view` | A finite app screen or vault gate becomes active | `app_surface`, allowlisted `screen_name` |
| `vault_unlocked` | Setup or unlock succeeds | `app_surface` |
| `vault_locked` | Manual or backend-driven lock succeeds | `app_surface` |
| `tracking_setup_started` | Tracking setup is opened from Activity | `app_surface` |
| `settings_saved` | Vault settings save succeeds | `app_surface` |
| `legal_document_opened` | An in-app privacy or terms link is opened | `app_surface`, `document` |
| `analytics_consent_granted` | The user enables analytics | `app_surface` |

Screen names are static categories such as `dashboard`, `projects`,
`project_detail`, `credential_form`, `repository_scan`, `usage`, `gateway`, and
`settings`. Dynamic route identifiers never enter the event. The desktop page
location is fixed to `https://usetethra.com/app` and its referrer is suppressed,
so local development origins and navigation state are not reported.

## Data that must never enter analytics

The landing implementation filters both event and parameter names at runtime.
The desktop implementation exposes a TypeScript discriminated union rather
than a generic event API. Do not add a free-form parameter escape hatch.

Prohibited data includes:

- credentials, fingerprints, master passwords, auth material, and vault data;
- project, credential, provider, model, route, process, and destination names;
- file/repository paths, env names or values, user-entered URLs, and notes;
- prompts, headers, request/response bodies, endpoints, query values, or logs;
- alert/error text, exact usage, token, latency, request, or cost values;
- email, names, account identifiers, or any other direct personal identifier.

## Retention and access

User- and event-level GA data must be retained for no longer than 14 months.
Only people operating Tethra's Firebase/Analytics property should have access,
and access should use least privilege. Analytics must not be linked to an ad
account, exported for advertising, or used to train an AI model.

The public legal disclosure is `landing/privacy.html`. Any new event or
processor requires a privacy review, an update to this inventory, and an
assessment of whether new consent is required before release.
