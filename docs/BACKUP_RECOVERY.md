# Backup & Recovery

API Tracker stores everything locally. If you lose the data directory and have
no backup, the data is gone — so back up regularly.

## Create a backup

```bash
api-tracker backup create ~/api-tracker-backup.json
```
Or use the desktop **Backup** screen. You choose a **backup password** (it can
differ from the master password). The file is a single AEAD-encrypted document;
credential values inside stay encrypted under their project keys.

A backup captures the **entire vault** — every table in the database
(projects, credentials and their retained versions, provider connections,
usage and cost history, alerts, scan suppressions, `.env` mappings and
exports, destinations, sync plans, rotations, access grants, documentation
watches, and notification channels). Backups created by older builds
(format v1) contained only projects, credentials, repositories, and the
audit trail; they still restore, preserving what they contain.

## Verify a backup

```bash
api-tracker backup verify ~/api-tracker-backup.json
```
Verification decrypts and validates the file without changing anything.

## Restore

```bash
api-tracker backup restore ~/api-tracker-backup.json        # into an empty vault
api-tracker backup restore --force ~/api-tracker-backup.json  # replace an existing vault
```
`--force` renames the current database aside (`vault.db.replaced-<ts>`) rather
than deleting it. After restore, unlock with the **master password that was in
effect when the backup was created**.

A backup made by an **older** version of API Tracker restores fine: the data
is imported at its original schema version and then upgraded to the current
one automatically. A backup made by a **newer** version is refused with a
clear error — restore it with that newer version instead.

## Recovery limits (by design)

- Restoring needs the **backup password**.
- Unlocking the restored vault needs the **master password from backup time**.
- There is **no password-recovery bypass**. Losing both makes the backup
  permanently unreadable. This is intentional — a recovery backdoor would
  undermine the encryption.

## Recommendations

- Keep at least one recent backup **off the machine** (external drive or your
  own encrypted cloud storage). The backup file is safe to store on untrusted
  storage because it is encrypted, but treat the passwords as secrets.
- Store the backup password in a separate password manager.
- Test a restore into a throwaway `--data-dir` occasionally so you know it
  works before you need it.
