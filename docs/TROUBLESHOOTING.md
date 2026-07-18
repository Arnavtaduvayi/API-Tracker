# Troubleshooting

## Launch / install

- **macOS "cannot be opened because the developer cannot be verified"** — the
  alpha is unsigned. Right-click → *Open* → *Open*, or run
  `xattr -dr com.apple.quarantine "API Tracker.app"`.
- **Windows SmartScreen "unrecognized app"** — *More info* → *Run anyway*.
- **Linux AppImage won't run** — `chmod +x` it; install `libfuse2` if it
  complains about FUSE.

## Vault

- **"the vault is locked"** (CLI) — run `api-tracker unlock` and
  `export API_TRACKER_SESSION="…"`, or set `API_TRACKER_PASSWORD` for
  non-interactive use.
- **"incorrect password"** — the master password is wrong. It cannot be
  recovered; restore from an encrypted backup if you have one.
- **"a vault already exists"** — `init` never overwrites. Use `--data-dir` for a
  separate vault, or restore into it explicitly.
- **Desktop and CLI show different data** — they must use the same data
  directory. Check `API_TRACKER_DIR` / `--data-dir`; the default is the
  platform data dir (see INSTALL.md).

## Providers, validation & usage

- **`key validate` fails with a network error** — validation makes a direct
  request to the provider; check connectivity and that the key is for that
  provider. A `401` means the provider rejected the key (marked invalid).
- **`usage sync` says "no admin credential connected"** — run
  `api-tracker provider connect <provider> <credential>` first with an
  admin/organization key. OpenAI/Anthropic usage APIs require an admin key.
- **Usage shows "not per key" / account-level** — that is the provider's
  attribution limit, reported honestly. Use manual usage entries
  (`usage record --credential …`) for per-credential budgets.
- **Costs look wrong** — they are **estimates** from a bundled pricing table.
  Set a manual override, or trust provider-reported cost when present.
  Estimates are flagged stale after 45 days.
- **`key permissions` empty for a GitHub token** — fine-grained tokens don't
  expose scopes via the API; only classic PATs do.

## `run` (process injection)

- **"no credentials to inject"** — pass `--credential X --env VAR` pairs or
  configure mappings with `api-tracker mapping set …`.
- **"credential is not in project"** — `run` only injects credentials from the
  named project; this is deliberate isolation.
- **The child didn't see the variable** — confirm the `--env` name matches what
  the program reads, and that you passed the command after `--`.

## Scanning & hooks

- **`git is not installed`** — repository scanning and the pre-commit hook need
  `git` on `PATH`.
- **The pre-commit hook doesn't block** — ensure `api-tracker` is on the `PATH`
  the git hook runs with; the hook skips (does not block) if it can't find the
  binary.

## Getting help

Open an issue with the command you ran, the (redacted) output, your OS, and the
version (`api-tracker --version`). **Never paste a real credential.**
