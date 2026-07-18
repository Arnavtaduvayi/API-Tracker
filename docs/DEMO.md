# Demo and smoke test

Two scripts exercise the full product using the real shared core
(`api-tracker-core`), a fully isolated throwaway vault, and **only fake
credentials**. No network request is ever made, and no real API key is
required or used.

> **Warning:** every credential value in the demo is a generated fake
> (`sk-proj-DEMO-FAKE-…`). Never send demo values to a real provider, and
> never reuse the demo passwords below for a real vault.

## The demo

```bash
bash scripts/demo.sh          # build the demo vault, tour it, then delete it
bash scripts/demo.sh --keep   # retain the demo vault for manual inspection
bash scripts/demo.sh --fresh  # replace a previously kept demo without asking
```

By default the demo creates an isolated vault in a fresh private `mktemp`
directory (the exact path is printed at the start and end of the run). For
the copy-pasteable commands below, give it a fixed location instead:

```bash
export API_TRACKER_DEMO_DIR="${TMPDIR:-/tmp}/api-tracker-demo"
bash scripts/demo.sh --keep
```

Either way, your real vault in the platform data directory is never
touched, and an existing kept demo is never deleted without `--fresh` or an
interactive confirmation. Credential values are generated at run time, so
they exist nowhere in this repository or its Git history.

### Demo passwords (fake, intentionally public)

| Purpose | Password |
| --- | --- |
| Master password | `demo-master-password-12345` |
| Project password (`demo-prod`) | `demo-prod-project-password` |
| Backup password | `demo-backup-password-12345` |

### What the demo builds

| Project | Environment | Credential | Expected status |
| --- | --- | --- | --- |
| `demo-dev` | development | `openai-main` | `active` (validation recorded) |
| `demo-dev` | development | `github-deploy` | `expired` (expiration 2025-12-31) |
| `demo-dev` | development | `stripe-webhook` | `expiring soon` (expires in ~7 days) |
| `demo-dev` | development | `anthropic-experiments` | `unused` (no recorded activity; the demo sets `unused_days = 0` so this surfaces immediately) |
| `demo-dev` | development | `payments-legacy` | `shared across projects` |
| `demo-prod` | production (password-locked) | `payments-live` | `shared across projects` (same value as `payments-legacy`) |

Along the way the demo:

- shows the **cross-project reuse warning** (the duplicate is refused until
  `--allow-duplicate`, and flags production↔development sharing);
- records **synthetic usage** (1M input + 1M output `gpt-4o` tokens →
  **$12.50 estimated**, attributed `exact credential`) against a **$5.00
  budget**, so `monitor` raises a high-severity **`over_budget` alert**
  (plus one `expired`, one `expiring_soon`, two `production_in_development`,
  and five `unused` alerts — 10 open alerts in total; with
  `unused_days = 0` every credential without recorded activity is flagged
  unused, which is all of them except the validated `openai-main`);
- creates and **verifies an encrypted backup**
  (`demo-vault.backup` in the demo directory);
- demonstrates **secure process injection**: the child process receives
  `OPENAI_API_KEY` while `API_TRACKER_PASSWORD` is absent from its
  environment; no `.env` file is written and no value is printed.

### Open the demo in the desktop app

Run the demo with `--keep` (and `API_TRACKER_DEMO_DIR` set as above), then:

```bash
cd apps/desktop
API_TRACKER_DIR="$API_TRACKER_DEMO_DIR/vault" npm run tauri dev
```

Unlock with the master password above. The desktop app reads the same vault
through the same core crate as the CLI. (With the default random directory,
substitute the path the demo printed.)

### Inspect the demo with the CLI

```bash
export API_TRACKER_DIR="$API_TRACKER_DEMO_DIR/vault"
export API_TRACKER_PASSWORD='demo-master-password-12345'   # or: api-tracker unlock
./target/release/api-tracker key list
./target/release/api-tracker alerts list
./target/release/api-tracker key status demo-dev/payments-legacy
./target/release/api-tracker key reveal demo-dev/openai-main
API_TRACKER_PROJECT_PASSWORD='demo-prod-project-password' \
  ./target/release/api-tracker project unlock demo-prod
```

### Delete the demo

```bash
rm -rf "$API_TRACKER_DEMO_DIR"    # or the path the demo printed
```

(Without `--keep`, the demo deletes itself when it finishes.)

## The smoke test

```bash
bash scripts/smoke.sh
```

Runs the release binary (production Argon2id — no test escape hatches)
against a throwaway vault under `mktemp -d` and verifies, end to end:

- vault creation; the 12-character password minimum (11 rejected, 12
  accepted); an existing vault is never overwritten
- correct and incorrect master password behavior, with no password echo in
  errors
- session locking and unlocking (revoked sessions are rejected)
- project creation and project-password locking (wrong project password
  rejected; reveal blocked while locked)
- credential encryption at rest (no plaintext anywhere in the data
  directory or backup file)
- secret redaction in list/show/JSON output, and no secret in error output
- expiration classification (`expired`, `expiring soon`)
- duplicate-key detection across projects
- usage recording and estimated-cost calculation ($12.50, labeled
  estimated)
- over-budget alert generation
- backup creation, verification (wrong backup password rejected), and
  restoration into a fresh directory
- desktop/CLI compatibility: `cargo test -p api-tracker-core --test
  shared_vault_smoke` opens the CLI-created vault through the same core
  crate the desktop app uses
- secure process injection: the child receives the mapped variable while
  `API_TRACKER_PASSWORD`, `API_TRACKER_SESSION`,
  `API_TRACKER_PROJECT_PASSWORD`, and `API_TRACKER_BACKUP_PASSWORD` — all
  deliberately live in the parent environment at that moment — are absent
  from the child's environment
- no plaintext `.env` file is ever created
- the OpenAI administrative connection lifecycle (offline, `--no-verify`):
  connect via environment, status labeled administrative with the key
  masked, no plaintext key anywhere on disk, offline usage report,
  disconnect with reauthentication
- `.gitignore` protection for databases, vaults, backups, `.env` files,
  logs, and generated demo files

The script prints one `PASS`/`FAIL` line per check and exits non-zero if
any check fails. It cleans up after itself unconditionally.
