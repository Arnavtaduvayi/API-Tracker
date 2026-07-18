# Threat Model

This describes what API Tracker protects, from whom, and — just as
importantly — what it cannot protect. It reflects the current
implementation (encrypted vault, projects/credentials, reuse detection,
backups, CLI sessions); it will be revised as scanning and provider
integrations land.

## Assets

1. Credential values (the secrets themselves) — primary asset.
2. Provider **administrative connection keys** (e.g. an OpenAI Admin API
   key) — a higher-value asset than a workload key: it grants
   organization-wide read access to usage, costs, projects, and key
   metadata. Encrypted under the vault key like credential values; it can be
   replaced or removed but never displayed, and removal deletes the
   ciphertext (`secure_delete`). Its compromise does not expose workload
   secrets but does expose organization activity and spend.
3. Credential/project metadata (names, providers, environments, notes,
   repository paths, timestamps) — sensitive but stored unencrypted inside
   the vault database file; see "Known trade-offs".
4. Synchronized usage/cost data and cached provider-side metadata (project
   names, key names, redacted key previews) — non-secret by the provider's
   definition, but reveals activity and spend; stored unencrypted like other
   metadata.
5. The master password and project passwords (never stored).
6. Backup files.
7. The local audit trail.

## Trust boundaries and data at rest

- One SQLite database (`vault.db`) in the user's data directory, file
  permissions restricted to the user (0700 directory).
- All credential values in the database are individually encrypted
  (XChaCha20-Poly1305) under per-project keys; the key hierarchy chains up
  to the Argon2id-stretched master password (ADR 0003).
- Backups are single files encrypted under a separate backup password.
- The CLI session splits state between an encrypted file (0600) and a token
  that exists only in the user's shell environment (ADR 0004).
- Repository scanning, git access, and the pre-commit hook run entirely
  locally: no source code, diff, or finding ever leaves the machine. Scan
  findings, alerts, and suppressions store no secret values (findings keep a
  redacted preview and a non-secret suppression key; the raw value lives only
  in a `#[serde(skip)]` in-memory buffer used for vault matching). ADR 0008.
- Outbound network use is limited to two things, both direct from the device:
  the **documentation watcher** (explicit user-selected official URLs,
  conditional GETs, 8 MiB body cap, stores only validators/hash/timestamps,
  no crawling); and **provider connectors** (validation, metadata, permission
  reads, and usage/cost sync) that send the credential only in a request
  header to the provider's own official API endpoint. No secret is ever sent
  to an API-Tracker-operated server. Connectors are built to the documented
  API shapes and tested offline against fixtures.
- The **OpenAI administrative connection** stores an Admin API key encrypted
  under the vault key (AAD binds it to this vault + provider). It is
  write-only after storage (replace/remove, never reveal); replacing,
  removing, or live-testing it requires master-password reauthentication;
  and `run` strips its environment variable from child processes. Sync
  errors, statuses, and alerts carry status text only — never the key.
- **Secure process injection** (`run`) decrypts only the selected credentials
  of one project and sets them in the child process's environment. It never
  writes a `.env` or prints values, and it refuses credentials from other
  projects. Caveat (documented, not a bug): once injected, the value lives in
  the child process's environment — visible to that process and anything that
  can read its environment (e.g. `/proc/<pid>/environ` on Linux, or malware
  running as the user). Injection narrows exposure versus a committed `.env`;
  it does not defeat an attacker already running as you.

## Adversaries and outcomes

| Adversary | Outcome |
| --- | --- |
| Thief with the powered-off device / stolen disk image | Gets ciphertext. Values are protected by Argon2id (64 MiB, t=3) + AEAD. Metadata (project/credential names, providers, notes) is readable — see trade-offs. |
| Someone who copies `vault.db` (cloud sync, backup leak) | Same as above. Keyed fingerprints prevent offline guess-confirmation of values. |
| Someone who obtains a backup file | Needs the backup password (Argon2id-stretched). Contents beyond that are the same ciphertext as at rest. |
| Attacker who can *modify* the database | AEAD + per-record associated data detect value tampering, truncation, and ciphertext swapping between records. Metadata edits (e.g., renaming, changing an expiration date) are NOT cryptographically detected. |
| Snooper at an unattended, *locked* machine | Needs the master password; reauthentication also gates reveal/copy/export inside live sessions. Auto-lock (default 15 min) bounds exposure of an unlocked app. |
| Malware running as the user | **Not defended.** It can keylog the master password, read process memory, read the session file plus environment, or capture the clipboard. Local encryption cannot beat an attacker inside your account. |
| Compromised OS, debugger, cold-boot/memory dump | **Not defended.** Zeroization is best-effort; plaintext exists in memory during use. |
| Malicious dependency in the user's own projects | Out of scope — once you paste a key into your app's environment, its safety is that app's problem. (Future scanning features reduce *accidental* exposure, not malicious exfiltration.) |

## Design decisions that follow from this model

- No password recovery bypass: a recovery mechanism is a backdoor. Losing
  the master password (or a project password) permanently loses that data;
  backups are the mitigation, and the UI/CLI say so at creation time.
- Wrong password and corrupted key material are indistinguishable (both are
  AEAD failures); we report "incorrect password" and provide `doctor` and
  backups for genuine corruption.
- Reveal/copy print deliberate, explicit warnings; clipboard contents are
  cleared best-effort after a configurable delay.
- The fingerprint key is per-vault and wrapped, so reuse detection cannot be
  turned into an offline oracle.
- Sessions expire on a sliding inactivity window and can be revoked by
  deleting the session file (`api-tracker lock`).

## Known trade-offs and open items

- **Metadata is not encrypted.** Project and credential names, providers,
  environments, notes, repository paths, timestamps, masked values, and
  fingerprints are stored as plaintext columns. Reading *credential values*
  still requires unlocking the vault (they are encrypted), but a database
  thief learns all the metadata, and `doctor` deliberately reports
  project/credential counts without unlocking. Listing and revealing
  credentials themselves DO require the master password. A future
  full-database encryption layer (e.g., SQLCipher or app-level metadata
  encryption) is a candidate ADR; users who consider metadata sensitive
  should treat the data directory itself as secret material.
- **Reuse fingerprints cross the project-password boundary within an
  unlocked vault.** The keyed fingerprint is available as soon as the vault
  is unlocked with the master password (the fingerprint key is wrapped by the
  vault key, not by any project password). So a holder of the master password
  — but not a given project's password — can still: (a) confirm a *guessed*
  value is present in a password-locked project via the reuse check, and
  (b) see a locked project named as a "shared with" match when listing an
  unlocked project that holds the same value. The locked project's actual
  credential *values* remain encrypted and unreadable without its password
  (reveal/copy stay blocked). This is an equality/existence leak across the
  intra-vault boundary, weaker than the "needs both" guarantee ADR 0003
  states for value confidentiality; ADR 0005 documents it. Treat the master
  password as sufficient to learn value-equality across all projects.
- Audit events are plaintext rows in the same database and are not
  tamper-evident.
- The session file's expiry timestamp is plaintext; an attacker with write
  access could extend it but still needs the environment token.
- No OS-level "lock on session lock" hook yet (listed in the spec; needs
  per-platform integration).
- The UI reveals values into DOM memory when explicitly requested; the
  webview's memory is not zeroized.
