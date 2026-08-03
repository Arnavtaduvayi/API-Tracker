# Troubleshooting

## Launch / install

- **macOS "cannot be opened because the developer cannot be verified"** —
  download the current notarized DMG from `usetethra.com`. Older or automated
  GitHub alpha builds may be unsigned; for those, right-click → *Open* →
  *Open*, or run `xattr -dr com.apple.quarantine "Tethra.app"` after verifying
  the published checksum.
- **Windows SmartScreen "unrecognized app"** — *More info* → *Run anyway*.
- **Linux AppImage won't run** — `chmod +x` it; install `libfuse2` if it
  complains about FUSE.

## Vault

- **"the vault is locked"** (CLI) — run `tethra unlock` and
  `export TETHRA_SESSION="…"`, or set `TETHRA_PASSWORD` for
  non-interactive use. (The legacy `api-tracker` command and `API_TRACKER_*`
  variable names still work; see
  [rebrand/TETHRA_MIGRATION_GUIDE.md](rebrand/TETHRA_MIGRATION_GUIDE.md).)
- **"incorrect password"** — the master password is wrong. It cannot be
  recovered; restore from an encrypted backup if you have one.
- **"a vault already exists"** — `init` never overwrites. Use `--data-dir` for a
  separate vault, or restore into it explicitly.
- **Desktop and CLI show different data** — they must use the same data
  directory. Check `TETHRA_DIR` / `--data-dir`; the default is the
  platform data dir (see INSTALL.md).

## Providers, validation & usage

- **`key validate` fails with a network error** — validation makes a direct
  request to the provider; check connectivity and that the key is for that
  provider. A `401` means the provider rejected the key (marked invalid).
- **`provider sync` says "no administrative connection"** — run
  `tethra provider connect openai` first (an OpenAI **Admin** key, not
  a normal API key; see `docs/OPENAI_SYNC.md`). For other providers, connect
  a vault credential: `provider connect <provider> --credential <c>`.
- **Sync fails with "rejected the credential" / connection `invalid`** — the
  provider returned 401/403: the admin key was revoked, mistyped, or lacks
  the required scopes. Reconnect with a valid key
  (`provider connect openai`), then `provider test openai`.
- **Sync fails with "network unavailable"** — offline or DNS/timeout
  trouble. Nothing was changed; previously synced data is still viewable.
  Retry when online (`provider sync openai` is always safe to retry).
- **"provider-reported costs are unavailable" note after a sync** — usage
  synced but the costs endpoint failed (often a scope limit). Usage is
  stored; costs will be retried next sync.
- **Data flagged STALE** — the last successful sync is older than the
  `provider_stale_days` setting (default 3 days). Run
  `tethra provider sync <provider>`.
- **Usage shows "provider key" / "not per key"** — that row's provider-side
  key id is not linked to a local credential. See suggestions with
  `provider keys openai`, then confirm with
  `provider link openai <key-id> --credential <project/name>`. Coarser
  levels (project/account) are the provider's own attribution limit,
  reported honestly.
- **Reported and estimated costs differ** — expected. Reported cost is the
  provider's own bill line; the estimate is computed locally from token
  counts and a bundled price table that does not model every discount
  (caching, batch, service tiers). Budgets use one configurable source:
  `tethra budget source`.
- **Costs look wrong** — check whether you are reading the **estimate**
  (labeled) or the provider-reported figure. Estimates can be overridden per
  model and are flagged stale after 45 days.
- **`key permissions` empty for a GitHub token** — fine-grained tokens don't
  expose scopes via the API; only classic PATs do.

## `run` (process injection)

- **"no credentials to inject"** — pass `--credential X --env VAR` pairs or
  configure mappings with `tethra mapping set …`.
- **"credential is not in project"** — `run` only injects credentials from the
  named project; this is deliberate isolation.
- **The child didn't see the variable** — confirm the `--env` name matches what
  the program reads, and that you passed the command after `--`.

## Scanning & hooks

- **`git is not installed`** — repository scanning and the pre-commit hook need
  `git` on `PATH`.
- **The pre-commit hook doesn't block** — ensure `tethra` (or the legacy
  `api-tracker` alias) is on the `PATH` the git hook runs with; the hook skips
  (does not block) if it can't find either binary.

## Getting help

Open an issue with the command you ran, the (redacted) output, your OS, and the
version (`tethra --version`). **Never paste a real credential.**
