# ADR 0016: Product gap closure — pricing, templates, account metadata, destinations, residual hardening

Status: accepted (2026-07-19)

This milestone closes the remaining feasible product gaps before full
manual UI testing. Database migrations v8–v10.

## Versioned pricing (migration v8)

The fixed 5-model table became a versioned, effective-dated dataset with
three origins — bundled (compiled in, per-entry source URL + verification
date), imported (reviewed JSON files, strictly validated), and manual
overrides — with cached-input, batch, and per-request price fields.

Decisions:

- **Estimation prices usage as of the usage window's date.** The previous
  design recomputed estimates with "current" prices on every overlapping
  re-sync, silently repricing history. Effective dating makes re-syncs
  deterministic: a window re-derives the estimate it originally got unless
  the user explicitly imports a backdated correction. Sonnet 5's documented
  September 2026 price change is represented as two dated records and is
  covered by tests.
- **Usage predating every known record extrapolates the earliest record
  backwards and says so in the estimate's note** — the alternative (no
  estimate for old usage) would silently zero historical reports, and
  inventing a number silently is forbidden.
- **Precedence: override > imported > bundled, then latest effective date**
  at equal model-match specificity. A user's local data always beats the
  bundled table.
- **Updates are reviewable by construction**: `pricing propose` writes a
  template of the currently effective records; the user verifies it against
  the provider's published pricing page, edits, and `pricing import`
  validates (negative/non-finite/overflow/malformed rejected, whole-file
  atomicity) and applies. Nothing is scraped and nothing changes without an
  explicit import. A `pricing_stale` alert flags records unverified for 45+
  days for models with recent estimated usage.
- Cached/batch rates are carried on records but the cached-token discount
  is **not** applied to estimates (usage snapshots do not break out cached
  tokens); the module documents that estimates can exceed the bill and that
  provider-reported cost is authoritative.
- Legacy `pricing_overrides` rows migrate forward as all-dates overrides.

## Templates and stack detection (migration v9)

Nine embedded TOML templates (validated at build time like provider
manifests; a test proves no template text matches any secret-detection
pattern). Applying a template creates/annotates a project and optionally
writes a names-only `.env.example` (never overwriting); credentials are
only ever added by the explicit printed commands — a template can never
introduce a secret value.

Stack detection is **deterministic rules plus a locally stored
confirm/dismiss history — not machine learning**, and every surface says
so. Signals: dependency manifests (package.json, requirements.txt,
pyproject.toml), lockfiles, framework config, workflow files, and `.env`
variable NAMES (values stay inside the redacting parser). Reads are
bounded (256 KiB/file), nothing is executed, nothing leaves the machine,
every suggestion lists its evidence and confidence, and the learned
dataset is listable, per-repo resettable, and fully deletable.

Rejected alternative: any network-assisted or model-based classification —
needless for the problem and incompatible with honest labeling.

## Provider-account metadata (migration v10)

A `fetch_account` connector capability stores only what official endpoints
report — GitHub `/user` (login, id, email, plan), Stripe `/v1/account`,
Supabase `/v1/organizations` (multiple orgs → a count, never a guess),
Anthropic `/v1/organizations/me` — each with its source endpoint and sync
time. OpenAI has no documented account-identity endpoint and is reported
unsupported; the user-entered org label is labeled "user-entered, not
provider-verified" everywhere. Manifests gained official console-login and
billing-portal URLs. Provider account passwords, recovery codes, MFA
material, and browser session data remain **intentionally excluded**
(FEATURE_MATRIX #16): API Tracker is not a password manager.

## Destination completion

- **AWS delete** is implemented with the official recovery-window
  semantics: `DeleteSecret` with `RecoveryWindowInDays=30`;
  `ForceDeleteWithoutRecovery` is never sent (a fixture test asserts the
  flag's absence). Every surface states the deletion is scheduled and
  cancellable via RestoreSecret.
- **Linux Secret Service** via libsecret's `secret-tool` behind the
  mockable `CommandRunner` (value on stdin, never argv). secret-tool exits
  nonzero both for not-found and real failures; stderr distinguishes them
  so a locked keyring is never misreported as an absent secret. Labeled
  "not yet exercised against a live Secret Service".
- **Windows Credential Manager** via the `keyring` crate. The core crate
  is `forbid(unsafe_code)`; direct Win32 FFI is impossible under that
  guarantee, and shelling out (cmdkey/PowerShell) would put secrets in
  argument lists or script text. Encapsulating the unsafe FFI in an
  audited dependency preserves both properties. A new `windows-latest` CI
  job compiles and tests the core crate on real Windows.
- **Deleting a secret AT a destination** is now a real workflow
  (`destination delete-secret`, desktop action): confirmed,
  reauthentication-gated, never touches the vault value.
- The capability matrix now also declares per kind: verification method
  (value read-back vs existence-only), required plan, possible charges,
  and testing status (fixtures vs live).
- **Doppler, 1Password Secrets Automation, and HashiCorp Vault were
  evaluated and deferred.** Each has an official API, but: 1Password
  Secrets Automation requires a Connect server or service-account
  infrastructure decision per user; HashiCorp Vault presumes a self-hosted
  server individual developers rarely run; Doppler duplicates the covered
  CI/deploy use cases (GitHub Actions, Vercel) for this audience. Against
  the standing rule — do not add destinations merely to increase the
  adapter count — none clears the value/maintenance bar today. The adapter
  system is additive; any of them can land later as one reviewed file.

## Residual hardening (Phases 8–10)

- **Master-password change** re-wraps the vault key (fresh salt); no data
  re-encryption. Backups made earlier still open with their original
  password — stated in every surface. ADR 0010's known follow-up.
- **Project-key rotation on password set/change/remove.** Re-wrapping the
  same key left the pre-password wrap recoverable from WAL remnants or old
  backups (documented residual in the threat model). A password operation
  now generates a fresh key and re-encrypts the project's values and
  retained versions in one transaction; old wraps become worthless.
- **WAL checkpoint (TRUNCATE)** on vault drop and after every password
  operation; `vault.db` and sidecars chmod 0600 on Unix. On Windows,
  permissions remain OS-inherited — `doctor` now says so (implementing
  untested ACL surgery from a non-Windows dev machine risked locking users
  out of their own vaults; revisit with real Windows CI coverage).
- **Symlink export refusal**, expired-export sweeps on session resume (not
  just full unlocks), and a bounded sweep of `.N.api-tracker-tmp-*` files
  orphaned by crashes (only recorded export directories, only files over
  an hour old).
- **Dead injection-session sweep** in the monitor (`ps -p` liveness probe,
  Unix): only a definitive not-found closes a row.

## Accepted residuals (documented, not fixed)

- Metadata (names, providers, notes, account identity incl. email) stays
  unencrypted inside the vault database — unchanged trade-off, restated in
  THREAT_MODEL.md.
- The session file's TTL is plaintext (attacker with file write access can
  extend auto-lock but still needs the environment token).
- PID reuse between spawn and kill remains theoretically possible.
- The CLI has no clipboard command by design (desktop copy has timed
  clearing; a CLI clipboard would add platform tooling for a path `reveal`
  already covers deliberately).

## Security implications

New encrypted-at-rest surfaces: none (pricing records, templates,
detection decisions, and account metadata are non-secret local data). New
egress: none — account sync uses the same provider endpoints and admin
credentials as existing syncs; detection and templates are fully local.
The keyring dependency is the one new security-sensitive dependency,
Windows-only, chosen precisely to preserve `forbid(unsafe_code)`.
