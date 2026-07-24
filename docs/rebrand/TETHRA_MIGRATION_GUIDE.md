# Tethra Migration Guide (from API Tracker)

Tethra is the new name of API Tracker. **No data migration is required or
performed.** The rename is compatibility-safe by design: your vault,
backups, sessions, git hooks, keychain entries, scripts, and CI keep
working unchanged.

## What changed

| Area | Before | Now |
|---|---|---|
| App name (Finder, window, notifications) | API Tracker | Tethra |
| macOS bundle | `API Tracker.app` | `Tethra.app` |
| Preferred CLI command | `api-tracker` | `tethra` |
| Preferred env vars | `API_TRACKER_*` | `TETHRA_*` |
| Release archives | `api-tracker-<target>.tar.gz` | `tethra-<target>.tar.gz` (contains both binaries) |

## What did NOT change (on purpose)

- **Your vault location:** still the same directory (macOS:
  `~/Library/Application Support/api-tracker/`), same `vault.db` and
  `session.json`. Tethra opens your existing vault exactly as before —
  nothing is moved, copied, or converted, and no new empty vault is created.
- **Encryption formats:** every ciphertext, session, and backup remains
  bit-compatible in both directions.
- **Backups:** old backups restore in Tethra; backups created by Tethra
  restore in old API Tracker builds (same format marker and version rules).
- **The `api-tracker` command:** still installed, byte-for-byte the same
  program as `tethra`. Existing scripts and automation keep working with no
  deprecation banner and unchanged machine-readable output.
- **Installed git hooks:** hooks installed by old builds keep running and
  are still recognized by `tethra hooks status` / `remove`. Newly installed
  hooks prefer `tethra` and fall back to `api-tracker` automatically.
- **Keychain/credential-manager entries:** default service/account names are
  unchanged; existing stored destination secrets remain reachable.
- **The macOS bundle identifier** (`dev.api-tracker.desktop`): unchanged, so
  macOS treats Tethra as an upgrade of the same app (notification
  permissions, saved state, TCC grants carry over).
- **Webhook payloads:** the `source: "api-tracker"` field is unchanged so
  existing receiver filters keep matching.

## Environment variables

Every variable has a preferred `TETHRA_*` name; the legacy `API_TRACKER_*`
name keeps working:

| Preferred | Legacy (still works) |
|---|---|
| `TETHRA_DIR` | `API_TRACKER_DIR` |
| `TETHRA_PASSWORD` | `API_TRACKER_PASSWORD` |
| `TETHRA_SESSION` | `API_TRACKER_SESSION` |
| `TETHRA_NEW_PASSWORD` | `API_TRACKER_NEW_PASSWORD` |
| `TETHRA_PROJECT_PASSWORD` | `API_TRACKER_PROJECT_PASSWORD` |
| `TETHRA_BACKUP_PASSWORD` | `API_TRACKER_BACKUP_PASSWORD` |
| `TETHRA_PROVIDER_ADMIN_KEY` | `API_TRACKER_PROVIDER_ADMIN_KEY` |
| `TETHRA_DESTINATION_AUTH` | `API_TRACKER_DESTINATION_AUTH` |
| `TETHRA_INSECURE_FAST_KDF` (debug builds only) | `API_TRACKER_INSECURE_FAST_KDF` |
| `TETHRA_GIT_*` tuning vars (debug builds only) | `API_TRACKER_GIT_*` |

**Precedence:** when both names of a pair are set, the `TETHRA_*` variable
wins — its presence is authoritative even when empty, so a set-but-empty
preferred variable means "none" rather than silently falling back to a
conflicting legacy value. If `TETHRA_DIR` and `API_TRACKER_DIR` are both
set to *different* paths, a warning is printed to stderr and `TETHRA_DIR`
is used; the locations are never combined. Secret values are never printed.

**Security note:** `tethra run` scrubs *both* prefixes (deny-by-default,
case-insensitive on Windows) from every injected child process. Only
`*_DIR` and `*_INSECURE_FAST_KDF` are child-safe.

## Sessions

`tethra unlock --print-export` prints **two** export lines — the legacy
`API_TRACKER_SESSION` line first (so old scripts that parse it keep
working), then the preferred `TETHRA_SESSION` line. `eval` leaves both set
to the same token; either variable resumes the session in either binary.

When clearing a session from your shell, unset **both** names:
`unset TETHRA_SESSION API_TRACKER_SESSION`. As a safety net for scripts
that unset only one, a session variable holding a stale or invalid token no
longer wedges scripting: if the session cannot be resumed and a password
variable is set, the CLI falls back to the password (a stale token without
a password still fails with the usual session error).

## Recommended (optional) migration steps

1. Start typing `tethra` instead of `api-tracker`. Nothing forces you to.
2. In new scripts and CI, use `TETHRA_*` variable names.
3. Reinstall the pre-commit hook (`tethra hooks install <repo>`) if you want
   the hook body to prefer the `tethra` binary — old hooks keep working
   either way.
4. Keep your shell exports as they are; change them at your convenience.

## Failure modes

There is no migration step that can fail and no state that can be lost by
upgrading or downgrading between the last API Tracker build and the first
Tethra build: both read and write the same vault, in the same place, with
the same formats.
