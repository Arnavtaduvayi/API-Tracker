# ADR 0002: Cryptography — Argon2id + XChaCha20-Poly1305 envelopes

Status: accepted (2026-07-17)

## Decision

- Password stretching: **Argon2id** (RustCrypto `argon2`), 64 MiB memory,
  3 iterations, 1 lane, 32-byte output, 16-byte random salt per wrap.
  Parameters are stored (JSON) next to every password-derived wrap and are
  always read back from storage, so they can be raised later without breaking
  old vaults.
- Authenticated encryption: **XChaCha20-Poly1305** (RustCrypto
  `chacha20poly1305`) with a random 24-byte nonce per envelope.
- Envelope layout: `[version: 1 byte][nonce: 24 bytes][ciphertext+tag]`.
  The version byte (currently `1`) allows future algorithm migration.
- Associated data (AAD): every envelope is bound to a context string naming
  the crypto version and the exact record it belongs to, e.g.
  `api-tracker:v1:credential-value:<vault_id>:<project_id>:<credential_id>`.
  Swapping ciphertexts between rows therefore fails authentication.
- Randomness: the OS RNG via `getrandom` for keys, salts, nonces, and
  session tokens.
- Memory hygiene: secrets live in `SecretString`/`SecretBytes` wrappers
  (`zeroize`-backed) that redact `Debug`/`Display`/`Serialize` output and
  zeroize on drop.

No custom constructions: the crate only composes audited RustCrypto
implementations.

## Why these primitives

- Argon2id is the current OWASP-recommended memory-hard KDF; the parameters
  sit in the recommended interactive range.
- XChaCha20-Poly1305's 24-byte nonce makes random nonce generation safe
  without bookkeeping (collision probability negligible at any realistic
  envelope count), unlike AES-GCM's 12-byte nonces.
- Both have mature, widely reviewed Rust implementations with zeroize
  support and no C dependencies.

## Test support

`API_TRACKER_INSECURE_FAST_KDF=1` switches `KdfParams::recommended()` to
weak parameters **in debug builds only** so the test suite stays fast.
Release builds ignore the variable. Vaults always unlock with their stored
parameters regardless.

## Alternatives considered

- AES-256-GCM: fine primitive, but 12-byte nonces make random generation a
  budget question; XChaCha removes the footgun.
- `age`/`libsodium` wrappers: more dependency surface than composing the two
  primitives we need; sequoia/openpgp far too heavy.
- scrypt/PBKDF2: PBKDF2 is not memory-hard; scrypt is fine but Argon2id is
  the current recommendation.

## Security implications and limits

AEAD authenticates ciphertext and AAD, so corruption, truncation, tampering,
and cross-row swaps are detected. A wrong password and a corrupted wrap are
indistinguishable by design (both are auth failures); `unlock` reports
"incorrect password" for both, and `doctor` + backups are the recovery path
for real corruption.
