# ADR 0004: CLI sessions — split token (Bitwarden-style)

Status: accepted (2026-07-17)

## Decision

`api-tracker unlock` generates a random 32-byte **session token**, encrypts
the vault key (plus any unlocked project keys) under that token, and writes
only the ciphertext to `session.json` (mode 0600) in the data directory. The
token is printed once as an `export API_TRACKER_SESSION=...` line and never
written to disk. Subsequent commands need both the file and the token.
`api-tracker lock` deletes the file. The session carries a sliding expiry
equal to the vault's auto-lock setting, refreshed on each use; expired
sessions are rejected and deleted.

Commands can alternatively run with `API_TRACKER_PASSWORD` set (ephemeral
unlock per command) for scripting and tests.

## Why

A CLI process exits after every command, so "stay unlocked" state has to
live somewhere. The split design means neither artifact alone is
sufficient: the file without the token is ciphertext; the token without the
file is a random number. This mirrors the widely deployed Bitwarden CLI
model, which users already understand.

## Alternatives considered

- Prompt for the master password on every command: secure but unusable, and
  it pushes users toward putting the master password in the environment
  permanently — strictly worse.
- A long-lived agent daemon (ssh-agent style): better isolation, much more
  machinery (socket auth, lifecycle); a good future upgrade.
- Storing the derived key in the OS keychain: platform-dependent; planned as
  an optional convenience later.

## Security implications

- An attacker who can read **both** the session file and the shell
  environment of the user can reconstruct the vault key while a session is
  active. This is equivalent to malware running as the user, which is
  outside the threat model's protection anyway (see THREAT_MODEL.md).
- The expiry timestamp in the session file is plaintext metadata; an
  attacker who can edit it could extend a session, but such an attacker has
  file-write access and still needs the token.
- Reveal/copy/export still require the master password even inside a live
  session, so a leaked session alone never exposes credential values through
  the CLI's own commands... with the caveat that a session holds the vault
  key itself, so an attacker with both halves bypasses the CLI entirely.
  The reauthentication requirement protects against an *unattended
  terminal*, not against key extraction.
