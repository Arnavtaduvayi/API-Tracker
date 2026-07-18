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
