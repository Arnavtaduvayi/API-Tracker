# Region-aware product analytics

Tethra uses the GA4 web stream `G-MJQHJ6JT5Z` in Firebase project
`usetethra`. Measurement analytics is on by default for users resolved to the
United States and remains opt-in elsewhere. A stored opt-out and Global Privacy
Control always override the regional default. Core product behavior never
depends on analytics.

This is pseudonymous measurement, not authentication and not guaranteed
anonymous under every privacy law. Tethra has no Firebase Authentication user
and sends no GA `user_id`. GA's first-party client identifier is the only
returning-user mechanism while analytics is enabled.

## Regional choice behavior

- Landing choice: local storage key `tethra.analytics-consent.v1`; change it
  with **Privacy choices** in the footer.
- Desktop choice: the same key in the Tauri webview's separate local storage;
  change it under **Settings -> Pseudonymous product analytics**.
- Firebase Hosting serves `/region.json` using its IP-derived country routing.
  U.S. responses enable measurement without an unsolicited banner; other or
  unresolved regions remain opt-in.
- The U.S. default is kept in memory rather than stored as affirmative consent,
  so a later session outside the U.S. returns to opt-in behavior.
- Before enablement: no `gtag.js`, no GA request, no Analytics cookie.
- When enabled: `analytics_storage=granted`; `ad_storage`, `ad_user_data`, and
  `ad_personalization` remain denied.
- Google Signals and ad personalization signals are disabled.
- On withdrawal: events stop, GA is disabled, consent is updated to denied,
  and accessible `_ga` cookies are cleared.
- A Global Privacy Control signal disables analytics even if a prior grant was
  stored. The desktop honors it when the webview exposes the signal.
- Landing collection runs only on the HTTPS production hosts, never from
  `file://`, localhost, or a developer preview.

## Landing events

| Event | When it fires | Parameters |
| --- | --- | --- |
| `landing_session_start` | An analytics-enabled page initializes | `page_type` |
| `landing_section_view` | A home-page section reaches 45% visibility, once per page | `page_type`, `section` |
| `installer_download_clicked` | A macOS or Windows installer CTA is clicked | `page_type`, `source` (`nav`, `hero`, `final`, `legal`), `platform` (`macos`, `windows`) |
| `navigation_clicked` | An instrumented navigation link is clicked | `page_type`, `destination` |
| `legal_document_opened` | Privacy or Terms link is clicked | `page_type`, `document` |
| `analytics_consent_granted` | The user selects Allow | `page_type`, fixed consent-banner source |

Website locations are normalized to `https://usetethra.com/`, `/privacy`,
`/terms`, or `/docs`, and referrers are suppressed in Tethra's GA configuration.

## Desktop events

| Event | When it fires | Parameters |
| --- | --- | --- |
| `app_session_start` | An analytics-enabled app webview session initializes | `app_surface=desktop` |
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
