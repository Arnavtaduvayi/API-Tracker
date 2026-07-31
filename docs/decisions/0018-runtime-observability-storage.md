# ADR 0018: Runtime-observability storage — same vault database, no column encryption

Status: accepted (2026-07-24; recorded retroactively 2026-07-26)

This decision shipped with ADR 0017 and migration v12 and has been in effect
since; ADR 0017 (§Decisions 7, §Security implications) and
`docs/observability/RUNTIME_OBSERVABILITY_ARCHITECTURE.md` §12 and
`docs/observability/DEVELOPER_GUIDE.md` already cite this ADR by number, but
the file itself was never written. This document records the already-made,
already-implemented decision so those references resolve; it introduces no new
behavior. The full DDL is in `crates/core/src/db.rs` (migration 12); the
rationale below is distilled from the architecture document that has governed
the implementation since it shipped.

## The problem this fixes

Migration v12 added nine tables of runtime-observation metadata
(`observation_sessions`, `observed_api_services`, `observed_endpoints`,
`runtime_request_events`, `runtime_metric_buckets`,
`credential_traffic_attributions`, `observation_compatibility_results`,
`observe_certificate_state`, `observe_internal_allowlist`). Two storage
questions needed an explicit answer: where these rows live, and whether they
are column-encrypted.

## Decisions

1. **The rows live in the single shared vault database**, not a side file:
   the same SQLite database the CLI and desktop already share via WAL, so the
   activity views, attribution, aggregation, retention, and backup/restore all
   operate over one store with the existing migration, backup-v2, and
   schema-guard machinery (ADR 0015). They inherit the same at-rest
   protections as every other operational table: `0700` data directory,
   `0600` database/WAL/SHM, `secure_delete=ON`, WAL truncation on lock.

2. **They are not additionally column-encrypted, deliberately.**
   - The product's encryption model encrypts **credential material** (values,
     version history, provider admin keys, destination auth, webhook URLs).
     Operational metadata is plaintext today throughout the schema:
     `process_sessions.command`, `usage_snapshots.provider`,
     `activity_events.detail`, `project_repos.path`, `env_exports.path` all
     reveal comparable information about what a developer runs and calls.
   - Column-encrypting `host` and `path_template` would defeat `GROUP BY`,
     turning every dashboard query into a full-table decrypt, while
     equivalent information stays legible in adjacent tables — a real
     performance and complexity cost for no real adversary reduction.
   - **The feature stores no secret material at all** (the privacy model's
     column allowlist has no field capable of holding a body, header value,
     cookie, query string, or raw URL), so there is nothing for column
     encryption to protect. The one secret in the subsystem — the local CA
     private key — is stored ONLY as vault-key ciphertext
     (`observe_certificate_state.key_ciphertext`) with an AAD binding to the
     certificate PEM, which is an encryption decision made in ADR 0017, not
     here.

3. **Whole-database encryption remains the correct future home for this
   concern.** If SQLCipher (or equivalent) is adopted later it covers these
   tables automatically; per-column carve-outs now would not compose with it.

## Alternatives considered

- **A separate metadata database file** — rejected: breaks foreign keys to
  `projects`/`credentials`, duplicates migration/backup machinery, and adds a
  second WAL lifecycle for no isolation benefit (same directory, same OS
  permissions).
- **Column encryption of host/path fields** — rejected for the reasons in
  Decision 2.
- **In-memory only (no persistence)** — rejected: the product surface
  (inventory, endpoint history, "last seen", rotation-lag evidence) requires
  durable metadata; retention defaults (7-day events, 90-day buckets) bound
  the window instead.

## Security implications

- An attacker with local file access to the database reads observation
  metadata (hosts, sanitized path templates, timing). The threat model
  already accepts this class for the rest of the operational schema; the
  privacy model bounds what such an attacker can learn (no bodies, no header
  values, no query values, no raw URLs, no credential material).
- Keyed credential fingerprints (ADR 0005) remain the only
  identity-of-a-secret stored anywhere, and they are useless without the
  vault-wrapped fingerprint key.

## Future limitations

- Any future feature persisting NEW runtime-derived columns must extend the
  privacy-model allowlist first (`docs/observability/
  RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md`) — the allowlist, not this ADR, is
  the gate.
- If a feature ever needs to store secret-adjacent runtime material, it must
  use vault-key AEAD envelopes with a new AAD constructor (crypto.rs `aad`),
  never a plaintext column; this ADR's "no column encryption" applies only to
  non-secret operational metadata.
