# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security
Advisories: <https://github.com/Arnavtaduvayi/API-Tracker/security/advisories/new>.
Do not open public issues for security reports. You should receive a
response within a week. Please include reproduction steps and affected
versions, and use only fake credentials in reproductions.

## Security model (what is implemented today)

- Credential values are encrypted at rest with XChaCha20-Poly1305
  (authenticated encryption) under random per-project keys.
- Project keys are wrapped by a random vault key; the vault key is wrapped
  by a key derived from the master password with Argon2id (memory-hard).
  Passwords are never stored, not even as hashes.
- Optional per-project passwords add a second wrapping layer; both the
  vault and the project password are then required.
- Every ciphertext is bound (via AEAD associated data) to the vault,
  project, and credential it belongs to, plus a crypto version — corruption,
  truncation, and ciphertext swaps between rows fail authentication.
- Randomness comes from the operating-system CSPRNG.
- Secrets in memory live in zeroize-on-drop wrappers that print
  `[REDACTED]` from Debug/Display/serialization; automated tests assert that
  credential values never appear in listings, errors, logs, audit events,
  backups, or the database file in plaintext.
- Revealing, copying, replacing, or exporting secrets requires re-entering
  the master password, even inside an unlocked session.
- The app auto-locks after a configurable inactivity period; CLI sessions
  expire on the same schedule.
- Backups are single files encrypted under a separate backup password.
- Duplicate detection uses a *keyed* fingerprint (BLAKE3 keyed hash with a
  vault-specific wrapped key), so database access alone does not enable
  offline guess-confirmation of credential values.
- No telemetry, no analytics, no crash reporting, and no Tethra-operated
  server. The only network traffic the app can produce is direct traffic from
  your device to endpoints you explicitly configure: official provider APIs
  (validation, metadata, usage/cost sync, confirmed rotation steps),
  destination APIs you add (e.g. GitHub Actions, AWS Secrets Manager),
  official documentation pages you watch, and webhook URLs you configure.
  Nothing is sent anywhere without an explicit user-configured reason, and
  alert webhook payloads carry metadata only — never secret values.

## What this does NOT protect against

Local-first reduces exposure; it does not make keys perfectly safe. Out of
scope, by honest necessity:

- **Malware running as your user** — it can read process memory, capture
  the clipboard, keylog your master password, or wait for an unlocked
  session.
- **An attacker at your unlocked machine or an unlocked vault left
  unattended** (auto-lock narrows, does not close, this window).
- **A compromised operating system, debugger access, or memory dumps** —
  zeroization is best-effort; plaintext exists in memory while you work
  with it, and language runtimes may copy buffers.
- **Clipboard sniffers** — copied values are cleared after a configurable
  delay, but any process may read the clipboard in the meantime.
- **Shoulder surfing / screenshots** while a value is revealed.
- **Malicious dependencies** in your own projects that read the environment
  or files where you ultimately use the keys.
- **Forgotten passwords** — there is deliberately no recovery bypass. Losing
  the master password (or a project password, for that project) makes the
  data unrecoverable.

## Supported versions

Pre-1.0: only the latest commit on `main` receives fixes.
