# ADR 0028: Consent-first product analytics

## Status

Accepted, 2026-07-31.

## Context

Tethra needs broad adoption and retention measurements while preserving its
local-first credential boundary. Generic analytics APIs are unsafe in a vault
product because a convenient string parameter can accidentally receive a
project name, path, provider, URL, error, or secret-adjacent value.

## Decision

Use the existing Firebase project's GA4 web stream with basic consent mode:

1. Analytics is disabled by default everywhere.
2. The Google script is not loaded until affirmative consent.
3. The landing site uses runtime event/parameter allowlists.
4. The desktop UI uses a discriminated TypeScript event union with only finite
   screen and action values.
5. No Rust core, vault, gateway, scanner, CLI, or Tauri IPC payload is exposed
   to Analytics.
6. Advertising storage, Signals, ad user data, and ad personalization remain
   disabled.
7. Declining analytics has no functional consequence.

The full schema and prohibited fields are in `docs/ANALYTICS.md`.

## Consequences

Tethra can measure broad sessions, screens, landing engagement, downloads, and
retention after opt-in. It cannot use Analytics for provider-level behavior,
errors, funnels containing user input, credential outcomes, usage/cost facts,
or project activity. Product questions requiring those fields remain unanswered
rather than expanding the privacy boundary.
