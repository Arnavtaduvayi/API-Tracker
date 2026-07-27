# Threat Model

This describes what Tethra protects, from whom, and — just as
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
- Outbound network use is limited to four things, all direct from the device:
  the **documentation watcher** (explicit user-selected official URLs,
  conditional GETs, 8 MiB body cap, stores only validators/hash/timestamps,
  no crawling); **provider connectors** (validation, metadata, permission
  reads, and usage/cost sync) that send the credential only in a request
  header to the provider's own official API endpoint; when the user
  explicitly opts in, the **loopback observation proxy** (`observe` /
  `run --observe`), which relays the user's own application traffic onward
  to the API hosts that application was already contacting — it originates
  no requests of its own; and, when the user explicitly enables it, the
  **Local Gateway** — a loopback-only reverse gateway that relays traffic
  from explicitly linked projects to their REGISTERED provider origins
  (compiled-in manifest or MAC-verified custom origins; never a
  client-chosen host). Once enabled it runs as a per-user login service —
  a standing local egress relay to those registered providers, disclosed
  as such at consent time (`docs/gateway/`). No secret is ever sent to a
  Tethra-operated server. Connectors are built to the documented API
  shapes and tested offline against fixtures.
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

- **`.env` governance** parses environment files purely textually (nothing
  is executed or interpolated), previews and findings are always masked, and
  import never modifies the source file. An explicit **export** writes a
  plaintext file deliberately: it requires master-password
  reauthentication, uses an atomic 0600 write, refuses Git-tracked targets,
  verifies `.gitignore`, warns in the file itself, records a redacted audit
  event, and (for temporary exports) is swept by cleanup with a
  content-hash check. An exported file is still plaintext on disk — that
  trade-off is the user's explicit choice, made loudly.
- **Credential version history** retains prior values encrypted under the
  same project key (AAD-bound to the version number, bounded retention,
  purged with the credential). A compromised master password therefore
  exposes recent *old* values as well as current ones; old values are
  normally revoked at the provider after rotation, and the history is what
  makes destination rollback real instead of aspirational.
- **Destinations** (macOS Keychain, Linux Secret Service, Windows
  Credential Manager, AWS Secrets Manager, GitHub Actions,
  Vercel) receive values only through an explicitly executed sync-plan step
  or an explicit export — never automatically. Destination administrative
  credentials (IAM keys, PATs, tokens) are encrypted under the vault key,
  masked in every listing, write-only (replace/remove, no reveal), and
  reauthentication-gated for removal. Their blast radius is real: an IAM
  key that can write secrets or a repo-admin PAT is elevated material —
  scope them minimally at the issuer. Once a value is written to a
  destination, its safety is governed by that destination's access model
  (GitHub/Vercel never return values; AWS read-back is used for
  verification). Keychain writes pass the secret via stdin, never argv.

- **Rotation** composes destructive provider-side operations (create,
  disable, revoke). Ordering bounds the blast radius: nothing destructive
  runs before destinations verified AND the new value validated live;
  revocation is last and is refused otherwise. Every step needs the master
  password again; scheduled rotations only raise alerts — there is no
  unattended executor. Rollback restores destinations/vault/Anthropic
  disable, but a revoked key is gone: the CLI says "irreversible" instead
  of pretending. Provider admin credentials therefore carry create/revoke
  power now; scope them minimally at the issuer.
- **Temporary access grants** are local controls: they bound what this
  machine injects (window, launch count, per-process kill timer) and can
  SIGTERM recorded child PIDs. They cannot claw back values a process
  already received, cannot constrain the provider credential, and the UI/CLI
  say both. `access end --kill` signals a PID recorded at spawn; PID reuse
  between spawn and kill is theoretically possible (bounded by OS PID
  cycling; an attacker who can forge session rows is already "malware as
  the user", which this model excludes).
- **Retained credential versions** expire after the configured rollback
  window (default 30 days); pruning relies on SQLite `secure_delete`
  overwriting freed pages — best-effort secure deletion, not a guarantee
  against forensic recovery of previously-checkpointed WAL frames.

- **Runtime API observation** (ADR 0017;
  `docs/observability/RUNTIME_OBSERVABILITY_THREAT_MODEL.md`) is a strictly
  LOCAL, opt-in observation proxy: it binds to loopback only, requires a
  per-session token on every proxied connection, and records **metadata
  only** — never request/response bodies, headers, cookies, authorization
  values, or query strings. It introduces one new high-value asset: the
  **per-vault CA private key** (ECDSA P-256) used to mint short-lived
  interception certificates. That key is encrypted under the vault key like
  credential values, its sensitive operations are reauthentication-gated,
  and it is never written to disk in plaintext. Outbound relaying enforces
  an SSRF policy both before *and* after DNS resolution (no loopback,
  link-local, private-range, or metadata-endpoint targets unless explicitly
  allowlisted), and upstream TLS is always verified against the bundled
  root store — verification is never disabled, and the tool never
  recommends disabling it in observed applications either.
- **Webhook notification channels** are user-configured outbound requests
  (https-only). The URL may embed a token the user chose to put there, so
  it is encrypted under the vault key and masked everywhere; payloads carry
  alert metadata only (alerts are secret-free by construction). Delivering
  to a user-chosen URL is the same egress posture as provider syncs — the
  tool acts for its local user and never for a third party.

## Adversaries and outcomes

| Adversary | Outcome |
| --- | --- |
| Thief with the powered-off device / stolen disk image | Gets ciphertext. Values are protected by Argon2id (64 MiB, t=3) + AEAD. Metadata (project/credential names, providers, notes) is readable — see trade-offs. |
| Someone who copies `vault.db` (cloud sync, backup leak) | Same as above. Keyed fingerprints prevent offline guess-confirmation of values. |
| Someone who obtains a backup file | Needs the backup password (Argon2id-stretched). Contents beyond that are the same ciphertext as at rest. |
| Attacker who can *modify* the database | AEAD + per-record associated data detect value tampering, truncation, and ciphertext swapping between records. Metadata edits (e.g., renaming, changing an expiration date) are NOT cryptographically detected. |
| Snooper at an unattended, *locked* machine | Needs the master password; reauthentication also gates reveal/copy/export **and credential deletion** inside live sessions (enforced in core, not by the UI). Auto-lock (default 15 min) bounds exposure of an unlocked app. |
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
  deleting the session file (`tethra lock`).

## Known trade-offs and open items

- **Metadata is not encrypted.** Project and credential names, providers,
  environments, notes, repository paths, timestamps, masked values,
  fingerprints — and, since gap closure, provider-reported account identity
  (organization ids/names, account email, plan) — are stored as plaintext
  columns. Reading *credential values*
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
- **Setting, changing, or removing a project password ROTATES the project
  key** (since ADR 0016): a fresh key is generated and every credential
  value and retained version re-encrypted, and the WAL is checkpointed and
  truncated afterwards — so wraps that predate the password (in WAL
  remnants of the live file) become worthless. One artifact class remains
  outside this fix, by nature: a **backup taken before the password was
  set** still contains the old wrap and old ciphertexts, openable by
  whoever holds the backup password plus the master password from backup
  time. Treat old backups with the sensitivity of the data they contained
  when they were made.
- **The master password can be changed** (`change-password`, desktop
  Settings): the vault key is re-wrapped under the new password and the
  WAL truncated. Backups made before the change still open with their
  original password (stated in-product); live CLI sessions keep working
  until they expire (the vault key itself is unchanged).
- **Backup files, `vault.db`, and its WAL/SHM sidecars are written
  owner-only (0600) on Unix**; the data directory is 0700, and locking the
  vault checkpoints and truncates the WAL so freed or rewritten pages do
  not linger in the sidecar. On Windows/non-Unix these permission
  tightenings are no-ops (no ACL is set), so the OS-inherited ACLs govern —
  `doctor` warns about this, and the data directory should be treated as
  sensitive there. Backup contents are AEAD-encrypted regardless.
- **The session file's TTL/expiry is plaintext** (only the session id is in
  the AEAD associated data); an attacker with write access to the session file
  could extend the auto-lock window, but still cannot decrypt anything without
  the environment-held token. Auto-lock is a convenience bound, not a
  cryptographic control.
- The session file's expiry timestamp is plaintext; an attacker with write
  access could extend it but still needs the environment token.
- No OS-level "lock on session lock" hook yet (listed in the spec; needs
  per-platform integration).
- The UI reveals values into DOM memory when explicitly requested; the
  webview's memory is not zeroized.
- **Templates, stack detection, pricing records, and account metadata add
  no secret material.** Detection reads a bounded set of static repository
  files locally (values in `.env` files never leave the redacting parser),
  its learned confirm/dismiss history is plain local data the user can
  delete entirely, and pricing/account records are non-secret metadata.
- **Runtime observation carries accepted residual risks** (ADR 0017;
  detailed in `docs/observability/RUNTIME_OBSERVABILITY_THREAT_MODEL.md`).
  While the vault is unlocked and an observation session is active, the
  per-vault CA private key is decrypted in this process's memory — malware
  running as the user can read it, consistent with the "malware as the
  user" exclusion above. Observation coverage is honest but incomplete:
  QUIC/HTTP-3 traffic bypasses the proxy entirely, and descendant
  processes that clear or ignore the injected trust/proxy environment
  variables go direct and unobserved — absence of recorded traffic is
  therefore not evidence of absence. Mode C (system trust store, separate
  opt-in) has a larger blast radius than the default per-run modes: until
  the certificate is removed, any process on the machine that trusts the
  system store would accept certificates minted by the vault's CA, so
  install/removal is reauth-gated and tracked in
  `observe_certificate_state` for cleanup.
- **Crash residue is swept**: expired temporary exports are cleaned on
  unlock *and* session resume, orphaned atomic-write temp files (older
  than an hour, only in recorded export directories) are removed, and the
  monitor closes injection-session rows whose recorded process died with
  its launcher (liveness probe; only a definitive not-found closes a row).
