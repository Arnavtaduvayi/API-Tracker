# Installation & First-Run Guide

Tethra is a **local-first** desktop app + CLI. There is **no account**, no
cloud service, and your secrets are never uploaded to a Tethra server.
This is an **alpha**: evaluate it carefully before storing highly sensitive
production credentials, and read the [security limitations](../SECURITY.md).

## Download

Get artifacts from the project's
[GitHub Releases](https://github.com/Arnavtaduvayi/API-Tracker/releases). Each
release lists a `.dmg` / `.msi` / `.AppImage` / `.deb` for the desktop app and
a standalone CLI archive per platform, plus a `SHA256SUMS.txt`.

### Verify the download (recommended)

```bash
# macOS/Linux
shasum -a 256 -c SHA256SUMS.txt      # or: sha256sum -c SHA256SUMS.txt
```
```powershell
# Windows
certutil -hashfile tethra-x86_64-pc-windows-msvc.zip SHA256
```

**These builds are unsigned (alpha).** You will see OS warnings:

- **macOS**: right-click the app → *Open* → *Open* (bypasses Gatekeeper once),
  or `xattr -dr com.apple.quarantine "Tethra.app"`. Gatekeeper flags it
  because it is not notarized.
- **Windows**: SmartScreen → *More info* → *Run anyway*.
- **Linux (AppImage)**: `chmod +x Tethra*.AppImage && ./Tethra*.AppImage`.

## Install the CLI

Unpack the archive and put `tethra` on your `PATH`:

```bash
tar -xzf tethra-<target>.tar.gz
sudo mv tethra /usr/local/bin/           # or anywhere on PATH
tethra --version
```

The archive also contains an `api-tracker` binary — the same program under
its old name, kept as a compatibility alias for existing scripts and hooks.
See [rebrand/TETHRA_MIGRATION_GUIDE.md](rebrand/TETHRA_MIGRATION_GUIDE.md).

## First run

Desktop: launch the app; it prompts you to create a vault and set a master
password. CLI:

```bash
tethra init                              # create the encrypted vault
eval "$(tethra unlock --print-export)"   # start a session
tethra project create my-app --env production
tethra key add --project my-app --name openai --provider openai \
    --environment production             # the secret is prompted, hidden
```

The desktop app and CLI share the **same vault** (same data directory), so you
can use both.

> **Recovery:** your master password is never stored and cannot be recovered.
> If you lose it, the vault is unrecoverable by design. Make encrypted backups
> (`tethra backup create <path>` or the desktop Backup screen).

## Where your data lives

The vault database (`vault.db`), CLI session file, and WAL files live in the
platform data directory; override with `--data-dir` or `TETHRA_DIR` (the
legacy `API_TRACKER_*` variable names still work).

| OS | Default data directory |
| --- | --- |
| macOS | `~/Library/Application Support/api-tracker/` |
| Linux | `~/.local/share/api-tracker/` (XDG `$XDG_DATA_HOME`) |
| Windows | `%APPDATA%\api-tracker\` (roaming) |

The directory keeps its historical `api-tracker` name so existing vaults are
found. Only encrypted credential values live there; metadata (names,
providers, notes) is stored unencrypted — treat the directory itself as
sensitive. See [THREAT_MODEL.md](../THREAT_MODEL.md).

## Backups

Create encrypted backups regularly and store them off-machine:

```bash
tethra backup create ~/tethra-backup.json
tethra backup verify ~/tethra-backup.json
```

Restoring needs **both** the backup password and the master password in effect
when the backup was made. See [BACKUP_RECOVERY.md](BACKUP_RECOVERY.md).

## Upgrade

To upgrade, replace the app/binary with a newer build — your vault stays put
in the data directory and is **not** touched by installing a new version.

- **Schema migrations run automatically** the first time a newer build opens
  the vault. Migrations are append-only and forward-only; there is no
  downgrade. A vault upgraded by a newer build **cannot** be opened by an
  older build afterward (you will get a clear "schema is newer than this
  build" error) — upgrade, don't downgrade.
- **Back up first.** Run `tethra backup create <path>` (or the desktop
  Backup screen) before a major upgrade. A backup made by an older build
  restores into a newer build and migrates forward; a backup made by a newer
  build cannot be restored by an older one.
- **CLI**: unpack the new archive and replace the binary on your `PATH`; run
  `tethra --version` to confirm.
- **Desktop**: install the new `.dmg`/`.msi`/`.AppImage`/`.deb` over the old
  one (or drag the new `.app` to Applications, replacing the old).

## Uninstall

1. Remove the app (drag to Trash on macOS / uninstall on Windows / remove the
   `.AppImage` or `sudo apt remove tethra` on Linux) and delete the CLI
   binary from your `PATH`.
2. Delete the data directory (table above) to remove your vault. **This is
   irreversible** — back up first if you may want the data later.
3. Remove any exported `TETHRA_SESSION` (or legacy `API_TRACKER_SESSION`)
   from your shell profile.
