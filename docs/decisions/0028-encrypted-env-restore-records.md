# ADR 0028 — Recorded `.env` prior values are encrypted, not judged

Status: accepted
Date: 2026-07-27
Amends: ADR 0019 D9

## Context

Linking a project to the gateway rewrites `OPENAI_BASE_URL` (and its peers) in
the user's `.env`. To undo that, Tethra records what each variable held before,
in `gateway_project_links.prior_env_json`.

That column is plaintext `TEXT` in an **unencrypted** SQLite file:
`crates/core/src/db.rs` opens the database with `Connection::open` and no
`PRAGMA key`. Encryption in this product is per-column
(`credentials.ciphertext`), and `prior_env_json` was not one of the encrypted
columns. Its readers are therefore: any process running as the user, with no
vault password and no keychain prompt; any file-level backup (Time Machine,
cloud sync, `rsync`); and any disk image. `restrict_db_permissions` sets 0600
best-effort, which stops other local users and nothing else.

ADR 0019 D9 handled this with a **shape predicate**,
`prior_value_is_recordable`: record the prior value only when it looks like
non-secret configuration (an `http`/`https` URL with no userinfo, no query, no
fragment and no key-material-shaped path segment, or a proxy-list-shaped
value). Otherwise withhold it, warn the user, and accept a manual restore.

An independent re-audit (finding `RA-006`, HIGH) showed the predicate admitting
values the codebase's **own** `looks_like_key_material` flags as key material:

| value | `prior_value_is_recordable` | `looks_like_key_material` |
|---|---|---|
| `sk-proj-AbCdEf123456.xyz789` | true | **true** |
| `admin:S3cr3tPassw0rd` | true | false |
| `AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMIK7MDENGbPxRfiCY` | true | **true** |
| a JWT (`eyJhbGciOi….eyJzdWIi….dQw4w9WgXcQ`) | true | **true** |

The last one is the sharpest: a Supabase `SUPABASE_SERVICE_ROLE_KEY` *is* a
JWT — a full RLS-bypassing admin credential — and `supabase` is a trackable
provider in this very catalog. The auditor also recovered a canary from raw
`vault.db` at byte offset 527996, and noted that the leaking case was
**silent** while the withheld case raised a warning.

The two predicates contradicted each other on the same input. That is the
signal that mattered: the design required a correct answer to "is this string a
secret?", and that question does not have a reliable answer.

## Decision

**Stop asking whether a value is secret. Encrypt every recorded value.**

`prior_env_json` v2 stores ciphertext. Each prior value is sealed with
XChaCha20-Poly1305 under a per-vault **env-restore key**, wrapped under the
vault key and stored in `vault_meta.wrapped_env_restore_key` — the same shape
as the existing `wrapped_gateway_mac_key` (`vault.rs`).

Associated data binds each ciphertext to its exact place:

```text
api-tracker:v1:env-restore-value:{vault_id}:{link_slug}:{path}:{key}
```

so a ciphertext moved to another variable, another file, or another link fails
to open rather than silently restoring the wrong secret somewhere else.

What stays in the clear is deliberately only the *structure*: which file, which
variable, whether the file existed, what Tethra wrote, and whether a value was
recorded at all. That keeps `unlink`'s reporting honest, and keeps the gateway
service's read-only "is there a restore record?" check working without giving
it a key it must never hold.

### Key custody

The env-restore key **can decrypt** — that is its job — so unlike
`gateway_matching_key` and `gateway_route_mac_key` it is never pushed over the
gateway control socket and never leaves a process with an unlocked vault. The
control protocol has no response variant that can carry a key, so this is
unrepresentable rather than merely forbidden.

Every production path that records or restores a prior value already holds an
unlocked vault (CLI `Ctx::unlocked`, desktop `with_vault`, tracking `apply`
which takes `&mut UnlockedVault`). The handle is threaded explicitly through
`apply_link`, `unlink`, `existing_prior` and `scrub_stored_prior_env` rather
than reached for implicitly.

### Failing safely

Without a key, a value is **withheld** — recorded as absent, surfaced as a
warning — never written in the clear. "We could not protect it" and "it is safe
to store" must not resolve to the same behaviour; that equivalence is what
`RA-006` was. In `apply`, failing to derive the key fails the step rather than
proceeding quietly.

### Legacy records

v1 documents hold plaintext and are still **read**, so an existing user can
still unlink after upgrading. On the next unlocked command they are
**re-sealed** in place and the version is bumped. Without a key they are
redacted rather than carried forward — but the one-time scrub is a deliberate
no-op when keyless, because redacting would take away an undo that a later,
unlocked call can still preserve.

The scrub therefore runs at **unlock**, not from `track status`/`track doctor`,
which hold no vault. Both front ends reach it through one function,
`envlink::upgrade_restore_records`:

* CLI — `apps/cli/src/ctx.rs`, from `Ctx::unlocked`.
* Desktop — `apps/desktop/src-tauri/src/main.rs`, from the `vault_unlock`
  command.

### Correction (`ENC-01`, 2026-07-28)

This paragraph previously claimed the same thing about "the desktop's unlocked
commands" **while that call site did not exist**. The only keyed caller was in
the CLI, so the persona this ADR names as the reason the work was done — a user
who never opens a terminal — was the one persona whose `RA-006` plaintext was
never re-sealed. It stayed in `vault.db` indefinitely.

The desktop call site now exists, and both front ends call the same function so
they cannot diverge again. `crates/gateway/tests/legacy_rollback_migration.rs`
asserts that both call sites are present and that the desktop's is on the
`vault_unlock` path; removing either fails the suite.

The migration is transactional (the row rewrite and the completion marker
commit together), idempotent, marker-guarded so a finished vault is never
re-scanned, and resumable — an interrupted pass leaves no marker, so the next
unlock repeats it. It records `envlink_prior_scrub_v1`,
`envlink_prior_scrub_version` and `envlink_prior_scrub_rows` in `vault_meta`;
those carry timestamps and counts, never a value. A row this build cannot parse,
or one a newer build wrote, is left byte-identical rather than rewritten by a
guess, and does not stop the rest of the pass.

After committing, the WAL is checkpointed and truncated. `secure_delete` (set in
`db::configure`) overwrites freed pages inside the database file; the WAL is a
separate file and needs the checkpoint. The residual limits are stated in
`docs/activity-onboarding/KNOWN_LIMITATIONS.md`: this leaves no copy in
`vault.db`, `vault.db-wal` or `vault.db-shm`, and it does **not** reach free
space elsewhere on the volume, a filesystem snapshot, a Time Machine copy, or a
backup taken before the upgrade.

## Alternatives considered

**Fix the predicate.** Raise the floors, consult `looks_like_key_material` on
the non-URL branch, remove the `v.len() < 8` placeholder exemption. This is
what the audit's `required_remediation` suggested, and it would have closed
every listed case. Rejected as the primary control for the same reason as
ADR 0027's enumeration: it leaves correctness resting on classifying arbitrary
user strings, and the next unusual shape defeats it. The predicate remains in
the tree only where it gates *display*, never storage.

**Store no prior value at all.** Safest, and it deletes the feature: undo
becomes manual for every variable, which is a large regression for the audited
"byte-for-byte undo" property.

**Back up the whole original file, encrypted.** Restores more faithfully, and
adds a second encrypted blob per link plus a new lifecycle. `envlink`'s module
doc already argues against a sibling backup file; the recorded prior state plus
the same-directory atomic temp write is the backup story. Reconsider if
per-variable restore proves insufficient.

**Encrypt the whole `prior_env_json` document.** Simpler to implement, and it
breaks the gateway service's presence check and `unlink`'s ability to report
which file and key it could not restore. Per-value sealing keeps the structure
legible to code that must not read the values.

## Security implications

* A recorded prior value is no longer readable from `vault.db`, its WAL, its
  SHM, a backup, or a disk image. Held by
  `crates/gateway/tests/restore_record_privacy.rs`, which sweeps raw bytes for
  ten deliberately awkward secret shapes and carries a negative control proving
  the sweep can find a planted needle.
* Secrecy no longer depends on recognising which strings are secret.
* Ciphertexts are bound to (link, file, variable) and cannot be transplanted.
* The blast radius of an unlocked vault is unchanged: a process with the vault
  key could already decrypt every credential.
* Undo is now *more* capable than before: values the old design withheld — a
  base URL with userinfo, one carrying a key in its query string — restore
  byte-for-byte.

## Future limitations

* A user who loses their vault password loses automatic restore for links made
  before that point. They keep the structural record (file, variable, what
  Tethra wrote), which is enough to undo by hand, and `unlink` says so.
* v1 records are re-sealed lazily, at the next unlock. A user who upgrades and
  never unlocks again keeps a plaintext record until they do.
* `prior_env_json` remains a plaintext-structured document. Adding a genuinely
  secret field to it in future would reintroduce this class of defect; the
  field-level rule is that anything derived from user file *content* must be
  sealed.
