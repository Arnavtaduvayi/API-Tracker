# ADR 0005: Keyed BLAKE3 fingerprints for reuse detection

Status: accepted (2026-07-17)

## Decision

Duplicate/reuse detection uses `blake3::keyed_hash(fingerprint_key,
trim(value))`. The 32-byte fingerprint key is random per vault and stored
wrapped under the vault key. Fingerprints are stored per credential and
indexed; matching fingerprints across records identify reuse of the same
secret value. Intentional sharing is modeled as a **reference** record that
points at the value-bearing credential and stores no second ciphertext.

## Why keyed (the spec's requirement, and the reasoning)

A plain public hash (SHA-256 et al.) of a credential would let anyone with
database access mount an offline confirmation attack: hash a guessed or
leaked key and check for a match — API keys have far less entropy structure
than passwords protects against. With a keyed hash, fingerprints are
meaningless without unlocking the vault first.

BLAKE3's keyed mode is a PRF with a native 32-byte key — no HMAC
construction needed, one fast dependency.

## Classification

Matches are classified relative to the credential being added/inspected:

- `duplicate_in_project` — same value twice in one project
- `production_shared_with_development` — value shared between production
  and development/test environments (highest-risk pattern)
- `across_projects` — independent copies in different projects
- `intentional_reference` — a reference record sharing the value on purpose

Each warning carries the affected records, a message, and a recommendation
(create separate provider credentials, or reference one entry).

## Trade-offs

- Values are trimmed before fingerprinting so whitespace paste accidents do
  not defeat detection; no other normalization is applied (a rotated key is
  a different credential, by design).
- Fingerprints reveal *equality* of values to someone holding an unlocked
  vault — that is exactly their purpose and does not weaken confidentiality
  at rest.
- **The fingerprint key is scoped to the whole vault, not to each project.**
  It is unwrapped as soon as the vault is unlocked with the master password,
  so reuse detection works across projects the master-password holder has
  not separately unlocked. This means value-equality (not the value itself)
  leaks across the project-password boundary: a master-password holder can
  confirm a guessed value exists inside a password-locked project, and a
  locked project can appear as a "shared with" match when listing an
  unlocked one. Reveal/copy of the locked project's values remain blocked
  (that needs the project password), so *confidentiality of the value* still
  requires both secrets — only *equality/existence* leaks. This is a
  deliberate trade-off for this milestone: per-project fingerprint keys would
  make cross-project reuse detection impossible for locked projects (the
  whole point of the feature). It is disclosed in THREAT_MODEL.md. A future
  option is to compute reuse matches only over currently-unlocked projects,
  at the cost of missing reuse involving locked ones.
