# ADR 0006: Encrypted backup format and restore semantics

Status: accepted (2026-07-17); payload design superseded in part by
ADR 0015 (2026-07-18): format v2 carries every table generically, and
older-schema backups are migrated after import as intended here.

## Decision

A backup is a single JSON file:

- Plaintext header: format marker (`api-tracker-backup`), format version,
  vault id, creation time, Argon2id parameters, salt.
- One AEAD envelope (base64) containing the full vault export: all
  `vault_meta` rows (including the wrapped vault/fingerprint keys), all
  projects (including wrapped project keys), repositories, credentials
  (ciphertexts as stored), and audit events, plus the database schema
  version.

The payload is encrypted with a key derived from a **backup password**
chosen at creation time. Credential values remain doubly protected: their
own project-key encryption is preserved inside the encrypted payload.

Semantics:

- `create` refuses to overwrite an existing file without an explicit flag,
  and requires master-password reauthentication (it is an export).
- `verify` fully decrypts and validates without writing anything.
- `restore` refuses to replace an existing vault unless forced; when forced,
  the current database is renamed aside (`vault.db.replaced-<ts>`), never
  deleted. Restore invalidates any CLI session. The restored vault unlocks
  with the master password in effect when the backup was created.
- Restore requires the backup's schema version to equal the version the
  running build writes. When future migrations exist, older backups will be
  migrated after import; version 1 is the only version today.

## Why

- A password-derived backup key makes backups safe to park on untrusted
  storage (cloud drives) and independent of the current master password.
- Including the wrapped keys keeps restore self-contained — no key escrow.
- JSON keeps the format inspectable (everything sensitive inside is
  ciphertext) and easy to version.

## Alternatives considered

- Copying the SQLite file and encrypting it: couples the backup format to
  SQLite internals (WAL state, page format) and prevents selective future
  evolution.
- Encrypting with the master-password KEK directly: would silently break
  every old backup on a future master-password change.

## Recovery limitations

Restoring needs the backup password; unlocking the restored vault needs the
master password from backup time. Losing both makes the backup permanently
unreadable — stated in the UI, CLI, and README.
