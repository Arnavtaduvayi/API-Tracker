# Destination Support Matrix

A **destination** is a place API Tracker can *deploy* a credential value to,
separate from the provider that *issues* it (see ADR 0012). Each kind reports
an honest capability matrix; run `api-tracker destination kinds` for the live,
per-kind status generated from the code — including, per kind, the
verification method, required plan, possible charges, and testing status.
Nothing is claimed that is not implemented.

Legend:
- **yes** — implemented and covered by fixture tests.
- **no** — the destination's API does not offer it (e.g. write-only secret
  stores never return values, so read is genuinely unsupported).
- **n/a here** — implemented, but unavailable on the current platform.

| Kind | Read | Write | Delete | Versioning | Rollback | Validate | Platform |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `vault` (source of truth) | yes | yes | yes | yes | yes | yes | all |
| `env_mapping` (local) | no¹ | yes | yes | no | no | yes | all |
| `env_export` (local file) | yes | yes | yes | no | yes | yes | all |
| `macos_keychain` | yes² | yes² | yes² | no | yes | yes² | macOS only |
| `linux_secret_service` | yes³ | yes³ | yes³ | no | yes | yes³ | Linux only |
| `windows_credential_manager` | yes⁴ | yes⁴ | yes⁴ | no | yes | yes⁴ | Windows only |
| `aws_secrets_manager` | yes | yes | yes⁵ | yes | yes | yes | all |
| `github_actions` | no⁶ | yes | yes | no | yes | yes | all |
| `vercel` | no⁶ | yes | yes | no | yes | yes | all |

¹ Local env mappings resolve at `run` time; there is no stored value to read
back — "write" just records the mapping.
² macOS Keychain is platform-gated; the secret is passed to `security(1)` on
**stdin**, never as a command-line argument.
³ Linux Secret Service goes through libsecret's `secret-tool` (value on
stdin, never argv). Needs the `libsecret-tools` package and a session
Secret Service (GNOME Keyring / KWallet). A locked keyring is reported as
an error, never as "secret absent". Not yet exercised against a live
Secret Service — the catalog entry says so.
⁴ Windows Credential Manager uses the `keyring` crate (CredWrite/CredRead/
CredDelete underneath); the core crate stays `forbid(unsafe_code)`. The
adapter compiles and core tests run on real Windows in CI; it is not yet
exercised against a live Credential Manager by CI.
⁵ AWS delete schedules deletion with the standard **30-day recovery
window** (cancellable with RestoreSecret until the deletion date);
`ForceDeleteWithoutRecovery` is never sent — a fixture test proves it.
⁶ GitHub Actions and Vercel secret stores never return secret values through
their APIs, so read is genuinely unsupported; write verification is
existence-only (value read-back is used only where a destination can
return the value, e.g. AWS and the OS stores).

## Deleting a secret at a destination

`api-tracker destination delete-secret <destination> <name>` (also in the
desktop Destinations screen) deletes the secret **at the destination**
after confirmation and master-password reauthentication. The value in the
local vault is never touched. AWS deletions are scheduled (see above);
other destinations delete immediately.

## Live verification status

The AWS, GitHub, and Vercel adapters follow the officially documented API
shapes and are covered by mock/fixture tests (including the official AWS SigV4
test vector); they have **not** yet been exercised against real accounts in
CI, and the catalog says so per kind. Safe, opt-in live-verification scripts
exist — each uses a throwaway vault, hidden credential prompts, one
disposable test secret holding a random FAKE value, typed confirmation
before any write, the strongest supported verification, and cleanup:

```bash
bash scripts/live_verify_aws.sh              # max expected cost < $0.05
bash scripts/live_verify_github_actions.sh   # free (use a throwaway repo)
bash scripts/live_verify_vercel.sh           # free (use a throwaway project)
```

macOS Keychain is exercised through a mockable `CommandRunner` and on real
macOS in CI; Linux Secret Service uses the same runner abstraction.

## Evaluated and deferred kinds

Doppler, 1Password Secrets Automation, and HashiCorp Vault each have
official APIs but were deferred (reasoning in ADR 0016): they add per-user
infrastructure decisions or duplicate covered use cases for individual
developers, and destinations are never added merely to increase the
adapter count. The adapter system is additive; any can land later.

## Security notes

- Every destination's administrative credential (an IAM key, a GitHub PAT, a
  Vercel token) is stored **encrypted under the vault key**, masked in every
  listing, and is write-only (replace or remove, never revealed);
  reauthentication is required to remove it. Scope these minimally at the
  issuer — a key that can write secrets or a repo-admin PAT is elevated
  material (see THREAT_MODEL.md). The OS credential stores need no stored
  credential (they use the OS session; the OS may prompt).
- A credential value reaches a destination **only** through an explicitly
  executed sync-plan step or an explicit export — never automatically. Sync
  plans are dry-run by default, reauthentication-gated to execute, verified
  per destination, and rolled back to retained versions where supported.
- A value placed in an OS credential store is governed by that store's own
  access model (readable by processes running as the user) — the same
  trust boundary as the OS session itself.
- The AWS region is validated against a plain region label before it is used
  to build the request host, so a crafted region cannot redirect the request
  (and the secret it carries) off-host.
