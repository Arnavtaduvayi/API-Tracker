# PR #13 — Threat-Model Delta

How the remediation changed the security posture of the runtime observability
feature. This complements `RUNTIME_OBSERVABILITY_THREAT_MODEL.md` (which was
itself corrected for honesty).

## Strengthened (net-positive security changes)

- **CA-cert laundering closed (RO-15).** The CA-key AAD now binds the
  certificate PEM. A DB-tampering attacker who swaps `ca_cert_pem` for their own
  CA (to get it installed into the OS trust store via a consented Mode C
  install) makes the key ciphertext fail to authenticate — `observe_ca_material`
  fails closed and the swapped cert can never be materialized or installed. This
  makes the threat model's "AEAD detects value tampering / ciphertext swapping"
  claim true for the one blob that feeds an OS-level trust decision.
- **SSRF defense-in-depth restored (RO-4/5).** Trailing-dot normalization stops
  `metadata.google.internal.` / `intranet.` from bypassing the metadata and
  single-label guards; NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) literals
  now decode their embedded IPv4 and are denied on hosts with a translator;
  `192.0.0.0/24` is denied.
- **Payload/secret retention tightened.** The event/service host is now the
  policy-validated CONNECT authority, never the spoofable client Host header
  (which could carry up to 32 KB of arbitrary bytes into the inventory). The
  path sanitizer no longer keeps low-character-class opaque tokens or 16–19-char
  mixed tokens verbatim, and its property test is no longer circular. The child
  command line is redacted before storage, so a secret passed in argv is not
  persisted in plaintext. `RequestHead`/`CertStateRow` `Debug` now redact.
- **Local DoS reduced.** An unauthenticated Slowloris is bounded to ~15 s by an
  absolute head-read deadline; session teardown force-closes in-flight client
  sockets so it cannot stall behind a blocked worker; the writer channel is
  bounded (no OOM under a request flood); worker handles are reaped.
- **Availability/honesty of the metadata (not a payload risk, but trust-in-
  tool).** Metric roll-up no longer bricks on a transport-error-only hour and no
  longer silently destroys un-aggregated events; alerts no longer crash the
  monitor cycle or fire permanent false positives; attribution no longer credits
  a key with traffic it did not send.

## New residual risks (documented, follow-up required)

- **RO-13 — vault lock does not interrupt a live run.** An active
  `run --observe` holds the vault key and the reconstituted CA signing key in
  memory for the monitored child's lifetime, regardless of a subsequent
  `lock`/auto-lock. Exposure window = child lifetime. Mitigations: Mode C off by
  default; the CA is a per-vault local observation CA; docs now state this
  plainly. A lock/auto-lock hook is required before public release.
- **Pinning / QUIC / client-handshake failures are not auto-detected.** These
  are documented limitations, not detections. An empty "full" dashboard is not
  proof of no traffic; the docs and UI say so, and detected unsupported runtimes
  (Go/Java/.NET) ARE flagged partial.
- **Env-inherited proxy token / port reuse; freed-heap key residue (rcgen
  leaf keys); `upstream_config` public field.** Unchanged inherent risks of
  env-based proxying and the rcgen dependency; no active leak; noted.

## Unchanged invariants (re-verified)

- Upstream provider certificates are always fully verified (no permissive
  verifier anywhere) — now enforced by `no_insecure_verifier.rs`.
- Loopback-only listener; per-session high-entropy token compared constant-time,
  never logged/persisted/serialized; DNS resolved once, connect only to a
  validated address.
- `ObservedRequest` is structurally incapable of holding a body, header value,
  cookie, query string, or raw URL — the metadata-only boundary is intact.
