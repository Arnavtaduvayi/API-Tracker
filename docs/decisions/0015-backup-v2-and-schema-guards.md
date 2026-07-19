# ADR 0015: Complete backups (format v2), older-backup migration, and schema guards

Status: accepted (2026-07-18)

## The problem this fixes

The alpha-completion audit found that the backup payload had silently fallen
out of sync with the schema: it carried only the five original v1 tables
(vault meta, projects, repos, credentials, audit events). Everything added by
migrations v2–v7 — alerts, suppressions, doc watches, provider connections,
usage/cost data, key links, env mappings, process sessions, credential
versions, env exports, destinations, sync plans, rotations, access grants,
notification channels — was **dropped on restore** while the documentation
described backups as a full vault backup. Separately, restore rejected any
backup whose schema version differed from the running build, contradicting
ADR 0006's stated intent to migrate older backups after import, and a vault
database written by a newer build would silently open read/write under an
older build.

## Decisions

1. **Backup format v2 is schema-generic.** The payload enumerates every user
   table from `sqlite_master` (name + columns + rows, typed cells, blobs
   base64). A future migration's new tables are included automatically — the
   backup can never fall out of sync with the schema again, by construction.
   Table/column identifiers are validated against a strict allowlist on both
   collection and restore, so a crafted payload cannot smuggle SQL.
2. **Format v1 stays readable.** Restoring a v1 file imports the five typed
   tables it actually contains (a v1-era build never captured more) into the
   current schema; the columns it names exist in every later schema.
3. **Older-schema backups migrate after import** (as ADR 0006 promised): a
   v2 payload is imported into a database rebuilt at the payload's schema
   version, then the normal migrations upgrade it to current. A payload
   schema **newer** than the build is refused.
4. **The plaintext format version is bound into the AEAD associated data**
   for v2 (`api-tracker:v1:backup-format2:<vault-id>`), so tampering the
   header cannot re-route an authentic payload to a different parser.
5. **Newer-schema live databases are refused.** `db::migrate` now errors
   (`SchemaTooNew`) when `user_version` exceeds the build's latest migration,
   instead of opening a newer vault read/write with unknown invariants. This
   guards every open path (unlock, CLI, desktop, restore).

## Alternatives considered

- Extending the typed v1 payload table-by-table: rejected — it is exactly
  the design that rotted; every future migration would need a matching
  backup change that nothing enforces.
- Copying the SQLite file (encrypted) instead of a logical export: rejected
  again for the ADR 0006 reasons (WAL/page-format coupling), and a logical
  export is what makes restore-then-migrate possible.
- Refusing older backups (status quo): rejected — a user's most likely
  restore scenario is an old backup into a freshly installed, newer build.

## Security implications

- The backup now contains strictly more (encrypted) material: notification
  channel URL ciphertexts, destination auth ciphertexts, provider admin key
  ciphertexts, and retained credential-version ciphertexts all travel inside
  the AEAD envelope, each already individually encrypted under vault-derived
  keys. The file remains safe to store on untrusted storage; its outer
  encryption still derives from the backup password.
- Restore executes generated `INSERT`s from decrypted data. Identifiers are
  allowlisted (`[A-Za-z0-9_]`), values are bound as parameters, and the
  target schema is built exclusively from the compiled-in migrations — a
  malicious payload can at worst fail to restore.
- Tests cover: full-table round-trip completeness (row counts across every
  table), legacy v1 restore + upgrade-after-restore, future format/schema
  rejection, header-demotion tamper detection, wrong password, tampered
  payload, populated v1/v5/v6 upgrades (direct and stepwise), interrupted
  migration resume, corrupted inputs, v7 backfill behavior, and
  future-schema refusal through the real unlock path.

## Future limitations

- v2 backups are larger (all tables, pretty-printed JSON); acceptable at
  individual-developer scale.
- Restore-then-migrate depends on append-only migrations (CONTRIBUTING.md
  already mandates this).
- A backup written by a FUTURE build (format > 2 or schema > current) needs
  that future build to restore; the error says so.
