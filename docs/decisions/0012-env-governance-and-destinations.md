# ADR 0012: `.env` governance, credential versions, destinations, and sync plans

Status: accepted (2026-07-18)

This milestone makes Tethra govern the place most developer secrets
actually live — `.env` files — and adds a second adapter system for the
places secrets are *deployed*. Database migration v5 adds
`credential_versions`, `env_exports`, `destinations`,
`credential_destinations`, `sync_plans`, and `sync_plan_steps`.

## `.env` parsing (`envfile.rs`)

A purpose-built lossless parser instead of a dotenv crate: the governance
features need round-trip fidelity (comments, blank lines, ordering, quoting
style, `export` prefixes, CRLF vs LF, inline comments), which loader-oriented
crates like `dotenvy` deliberately discard. Parsing is purely textual —
nothing is executed or interpolated (`$(...)`, backticks, and `$VAR` stay
literal). Raw lines and values live in `SecretString` (redacting, zeroizing),
so neither `Debug` nor serialization can leak a value. Malformed lines are
preserved verbatim on rendering and reported as problems, never dropped.

## Governance semantics (`envgov.rs` + vault methods)

- **Discovery** walks registered repositories (bounded depth, build
  directories skipped, symlinks not followed) for `.env` and `.env.*`;
  `.env.example/.sample/.template/.dist` are classified as templates and are
  never imported from. Environment is inferred from the file name. Git
  status is per-file: tracked / ignored / untracked, plus an independent
  "appears in Git history" flag (deleting a file does not delete history).
- **Import** is preview-first and selective; by default only values the
  scanner flags as likely secrets qualify, and placeholders/empties never
  do. Imported values are stored exactly like hand-added credentials and an
  injection mapping (`credential_env_mappings`) is created automatically, so
  `api-tracker run` works immediately. Values already in the vault are
  **mapped, not duplicated** (same project) or reported with reference
  guidance (other project). The source file is never modified by import.
- **Migration** is the guided path: detect → import+map → verify every
  detected secret resolves from the vault → show a masked diff → remove
  plaintext only after confirmation. Rollback is *re-export from the vault*
  rather than a plaintext backup copy: the values are provably in the vault
  (the verification step gates on it), so a backup file would only add
  another plaintext artifact.
- **Export** is the explicit escape hatch and is deliberately unpleasant to
  misuse: master-password reauthentication, target path + variable list
  shown first, refusal to overwrite without a flag, **refusal to write into
  a Git-tracked file at all**, atomic write (same-directory temp file, 0600,
  fsync, rename), `.gitignore` verification with warnings, a plaintext
  warning banner inside the file itself, a redacted audit event, and an
  optional TTL. Temporary exports are swept by `env cleanup`; a file whose
  content changed since export is not deleted without `--force` (the user
  may have added unrelated values).
- **Drift** compares fingerprints, never plaintext: file values are hashed
  with the vault's keyed BLAKE3 fingerprint and compared against stored
  credentials. Kinds: diverged mapped value, unmapped secret, production
  value in a dev/test file, one value copied into several files, template
  variables nothing provides, and mappings not present in any file (info —
  normal under `run`). The user chooses the source of truth; nothing
  synchronizes automatically.

## Credential version history

`replace_credential_value` now retains the outgoing value in
`credential_versions`, re-encrypted under the same project key with AAD
binding vault, project, credential, **and version number** (rows cannot be
swapped between versions). Retention is bounded (last 10); deleting a
credential purges its history (`ON DELETE CASCADE` + `secure_delete`).
History listing is reauthentication-gated and masked. The retained versions
exist for one purpose: destination rollback with real material instead of a
prayer. This also fulfils the "credential version history" product
requirement (previously: none).

## Destinations (`destinations.rs`) — separate from providers

A provider connector manages a credential *at its issuer*; a destination
adapter manages *where the value is deployed*. Conflating them would force
one trait to carry two lifecycles, so they are separate systems with
separate catalogs. Every destination kind reports an explicit capability
matrix (read / write / delete / versioning / rollback / validation), auth
requirements, platform support, and an implementation-status sentence — the
same honesty contract as provider manifests (nothing is claimed that is not
implemented; GitHub/Vercel are declared read-`unsupported` because those
APIs never return secret values).

Initial kinds: the local vault (source of truth), local env mappings
(no-write-needed by design — injection resolves at run time), tracked `.env`
exports, macOS Keychain, AWS Secrets Manager, GitHub Actions repository
secrets, and Vercel project environment variables.

Implementation notes:

- **macOS Keychain** shells out to the system `security` tool behind a
  `CommandRunner` trait (mockable). Writes go through `security -i` with the
  command on **stdin**, so the secret never appears in an argument list
  (visible via `ps`). Values with control characters are rejected rather
  than escaped creatively. Platform-gated: configuring it off-macOS fails
  honestly.
- **AWS Secrets Manager** signs requests with a from-scratch SigV4
  implementation (HMAC-SHA256 over RustCrypto `hmac`/`sha2` — request
  *signing*, not new cryptography) verified against the official published
  test vector (the IAM `ListUsers` example signature matches exactly).
  Write = `PutSecretValue` with `CreateSecret` fallback; read-back
  verification via `GetSecretValue`. Delete (with its recovery-window
  semantics) is declared `supported_not_implemented` rather than half-done.
- **GitHub Actions** encrypts with a libsodium sealed box (`crypto_box`
  crate, RustCrypto) to the repository public key, as the API requires;
  verification is existence-only because GitHub never returns values.
- **Vercel** uses the documented upsert endpoint with `type: "encrypted"`;
  verification is existence-only for the same reason.
- Destination admin credentials (IAM keys, PATs, tokens) are encrypted
  under the vault key with AAD `api-tracker:v1:destination-auth:{vault}:{id}`
  — the same write-only pattern as provider admin keys (ADR 0011): replace
  or remove, never reveal.

All destination traffic originates from the local machine; adapters are
fully covered by `MockHttpClient`/`CommandRunner` fixtures, so builds and
tests never need live accounts. The AWS/GitHub/Vercel adapters follow the
documented API shapes but have not yet been exercised against live accounts
— their catalog entries say exactly that.

## Synchronization plans (`syncplan.rs`)

A value change produces a reviewable plan: provider credential, old/new
version numbers with masked values, every configured destination with its
planned action (`write` / `reexport` / `none` / `manual`), validation
method, rollback availability, and affected projects (including reference
holders). Semantics:

- **Dry run is the default** — `sync plan` writes nothing anywhere.
- **Execution** requires explicit confirmation plus master-password
  reauthentication, supports per-destination rollout, verifies each write
  (fingerprint read-back where the destination can return values, existence
  otherwise), records per-step results, and marks the plan
  `partially_failed` when any step fails. Retry re-runs only pending/failed
  steps.
- **Stale plans refuse to run**: if the credential's version moved after
  plan creation, execution aborts and the plan is marked stale — a plan
  never silently deploys a value the user did not review.
- **Rollback** writes the retained previous version back to executed
  destinations (and re-exported files). It restores destinations only; the
  vault keeps its current value, stated explicitly in the CLI output.
- Old provider keys are **never revoked** by this milestone, and no
  destination write ever happens outside an explicitly executed plan step
  or an explicit export.

## Alternatives considered

- `dotenvy`/`dotenv` for parsing — rejected: loaders discard comments,
  ordering, and quoting, which migration and example generation must
  preserve.
- The official AWS SDK for Rust — rejected for now: it drags in tokio and a
  large dependency tree for one signed POST; SigV4 against the published
  test vector is small, offline-testable, and swappable later.
- Auto-executing sync plans on value change — rejected: silent writes to
  CI/cloud stores are exactly the class of surprise this product exists to
  prevent.
- Storing plaintext backups for migration rollback — rejected: re-export
  from the vault provides rollback without a second plaintext artifact.

## Security implications

- The blast radius of a destination admin credential (an IAM key that can
  write secrets, a PAT with repo admin) is comparable to the provider admin
  key and is documented in THREAT_MODEL.md; encrypted at rest, write-only,
  reauth to remove.
- Exported `.env` files are plaintext by definition; every path that
  produces one says so, restricts permissions, verifies `.gitignore`, and
  offers TTL cleanup. Export into a Git-tracked file is refused outright.
- Version history increases what a compromised master password can decrypt
  (old values as well as current). Old values are usually revoked at the
  provider after rotation; retention is bounded and purged with the
  credential. Judged acceptable for working rollback.

## Future limitations

- AWS delete, HashiCorp Vault / Doppler / 1Password kinds, and Windows/Linux
  keychain equivalents are not implemented (catalog says so).
- Live verification of remote destinations awaits real accounts
  (fixture-verified today).
- Drift checks run on demand; monitor-driven scheduling is a future
  milestone.
