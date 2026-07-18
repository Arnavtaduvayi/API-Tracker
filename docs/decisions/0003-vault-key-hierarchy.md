# ADR 0003: Vault key hierarchy and project password locks

Status: accepted (2026-07-17)

## Decision

```text
master password ──Argon2id──▶ KEK ──wraps──▶ vault key (random 32 B)
vault key ──wraps──▶ fingerprint key (random 32 B)
vault key ──wraps──▶ project key (random 32 B per project)
password-locked projects:
  vault key ──wraps──▶ [ project-password KEK ──wraps──▶ project key ]
project key ──encrypts──▶ each credential value
```

- Passwords are never stored, not even as verifier hashes: a wrong password
  simply fails to unwrap the vault key (AEAD authentication failure).
- Reauthentication (`reveal`, `copy`, value replacement, backup export)
  re-runs the full Argon2id derivation and unwrap.
- A password-locked project needs **both** the unlocked vault and its own
  password: the outer wrap is under the vault key, the inner wrap under the
  project-password KEK. Unlocked project keys are held only in memory (and,
  for the CLI, in the encrypted session payload).
- Removing or setting a project password requires proving knowledge of the
  current secret (project password for removal; an unlocked project for
  setting).

## Why

- Wrapping (rather than deriving data keys directly from passwords) lets a
  future "change master password" feature re-wrap one key instead of
  re-encrypting every row.
- Per-project keys keep a future scoped-sharing/export story possible and
  bound the blast radius of any single-key compromise.
- The double wrap gives project passwords real cryptographic teeth instead
  of being a UI-level gate.

## Recovery limitations (documented behavior, not bugs)

- Lose the master password → the vault is unrecoverable.
- Lose a project password → that project's credential values are
  unrecoverable, even with the master password.
- There is deliberately no recovery bypass; encrypted backups are the safety
  net.

## Alternatives considered

- Single vault-wide data key: simpler, but no per-project locks and larger
  blast radius.
- Project keys derived from master+project passwords directly: would make
  password changes require re-encrypting all rows.
- OS keychain integration for convenience unlock: deferred; documented as
  future work (optional convenience only, never the only path).
