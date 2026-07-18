# ADR 0010: Minimum password length raised to 12 characters

Status: accepted (2026-07-18)

## Decision

`MIN_PASSWORD_LEN` moves from 8 to **12** characters. The single constant in
`crates/core/src/vault.rs` governs newly chosen **master**, **project**, and
**backup** passwords (all three call sites validate through it). User-facing
guidance (desktop vault-setup screen, CLI `init`) now recommends a long
multi-word passphrase rather than a minimally compliant password.

Enforcement happens only where a password is **set**:

- `create_vault` (master password)
- `set_project_password` (project password)
- `create_backup` (backup password)

Unlock, project unlock, `backup verify`, and `backup restore` deliberately do
**not** validate length, so vaults, locked projects, and backup files created
under the old 8-character policy keep working unchanged. No migration is
needed and no existing user data is affected.

## Why

This vault protects API credentials — high-value, directly monetizable
secrets. The at-rest defense is Argon2id (64 MiB, t = 3) plus AEAD, but a
memory-hard KDF only multiplies the cost of guessing; it cannot rescue a
short password. An 8-character minimum admits passwords weak enough that an
offline attacker with the stolen database and modest GPU resources could
realistically exhaust them despite Argon2id. Twelve characters is the floor
current OWASP/NIST-aligned guidance treats as reasonable for high-value
secrets when paired with a memory-hard KDF; length is the one factor the
user fully controls.

## Alternatives considered

- **Strength estimation (zxcvbn)**: better signal than raw length, but pulls
  a nontrivial dependency (or a WASM/JS split-brain) into the
  security-sensitive core for the alpha. A candidate follow-up; length is a
  floor, not a ceiling, and the two compose.
- **Breached-password lists**: requires either bundling large lists or a
  network check (rejected outright — local-first, and a network check would
  leak password material derivatives).
- **Diceware-style enforced passphrases** (require N words): stronger in
  theory, but hostile to users with existing password-manager-generated
  random strings, which are excellent passwords.

## Security implications

Strictly stronger for new vaults/projects/backups. No change to stored data,
KDF parameters, or formats. Existing short-password vaults keep unlocking.
Note that restoring a backup reinstates the master password that was in
effect when the backup was created, so a backup/restore cycle does **not**
change the master password. Until a "change master password" flow lands
(future work; it will enforce the new minimum), the only upgrade path for an
existing short-password vault is to create a new vault with a stronger
password and re-add the credentials manually.

## Future limitations

A 12-character minimum still admits weak choices ("passwordpass"). The
recommended follow-up is a strength meter in the desktop setup screen and
CLI feedback, with zxcvbn-class estimation, once the dependency question is
settled.
