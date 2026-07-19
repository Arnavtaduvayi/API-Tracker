# Destination Support Matrix

A **destination** is a place API Tracker can *deploy* a credential value to,
separate from the provider that *issues* it (see ADR 0012). Each kind reports
an honest capability matrix; run `api-tracker destination kinds` for the live,
per-kind status generated from the code. Nothing is claimed that is not
implemented.

Legend:
- **yes** — implemented and covered by fixture tests.
- **not impl.** — the destination supports it officially, but API Tracker does
  not implement it yet (declared, not faked).
- **no** — the destination's API does not offer it (e.g. write-only secret
  stores never return values, so read is genuinely unsupported).

| Kind | Read | Write | Delete | Versioning | Rollback | Validate | Platform |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `vault` (source of truth) | yes | yes | yes | yes | yes | yes | all |
| `env_mapping` (local) | no¹ | yes | yes | no | no | yes | all |
| `env_export` (local file) | yes | yes | yes | no | yes | yes | all |
| `macos_keychain` | yes² | yes² | yes² | no | yes | yes² | macOS only |
| `aws_secrets_manager` | yes | yes | not impl.³ | yes | yes | yes | all |
| `github_actions` | no⁴ | yes | yes | no | yes | yes | all |
| `vercel` | no⁴ | yes | yes | no | yes | yes | all |

¹ Local env mappings resolve at `run` time; there is no stored value to read
back — "write" just records the mapping.
² macOS Keychain is platform-gated: configuring it off macOS fails honestly.
The secret is passed to `security(1)` on **stdin**, never as a command-line
argument.
³ AWS Secrets Manager delete carries recovery-window semantics; it is declared
`supported_not_implemented` rather than half-built.
⁴ GitHub Actions and Vercel secret stores never return secret values through
their APIs, so read is genuinely unsupported; write verification is
existence-only (fingerprint read-back is used only where a destination can
return the value, e.g. AWS).

## Live verification status

The AWS, GitHub, and Vercel adapters follow the officially documented API
shapes and are covered by mock/fixture tests (including the official AWS SigV4
test vector); they have **not** yet been exercised against real accounts in
CI. The catalog and this table say so. macOS Keychain is exercised through a
mockable `CommandRunner`.

## Security notes

- Every destination's administrative credential (an IAM key, a GitHub PAT, a
  Vercel token) is stored **encrypted under the vault key**, masked in every
  listing, and is write-only (replace or remove, never revealed);
  reauthentication is required to remove it. Scope these minimally at the
  issuer — a key that can write secrets or a repo-admin PAT is elevated
  material (see THREAT_MODEL.md).
- A credential value reaches a destination **only** through an explicitly
  executed sync-plan step or an explicit export — never automatically. Sync
  plans are dry-run by default, reauthentication-gated to execute, verified
  per destination, and rolled back to retained versions where supported.
- The AWS region is validated against a plain region label before it is used
  to build the request host, so a crafted region cannot redirect the request
  (and the secret it carries) off-host.
