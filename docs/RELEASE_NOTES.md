# API Tracker — Alpha Release Notes

API Tracker is a **local-first** desktop app + CLI for individual developers to
organize, secure, monitor, and manage the API credentials scattered across
their projects. There is no account, no cloud service, and no API-Tracker
server: the only network traffic is direct, from your device to endpoints you
explicitly configure (provider APIs, deployment destinations, watched docs
pages, and webhook URLs).

> **This is alpha software and the builds are UNSIGNED.** Evaluate it carefully
> before storing highly sensitive production credentials. Local-first reduces
> exposure but does **not** eliminate local-device risk (malware, an unlocked
> machine, memory inspection). See [SECURITY.md](../SECURITY.md) and
> [THREAT_MODEL.md](../THREAT_MODEL.md).

## What works end to end

Encrypted local vault (Argon2id + XChaCha20-Poly1305, per-project keys,
optional per-project password locks); projects and credentials with an
explainable status engine; keyed-fingerprint reuse detection; complete
encrypted backups (every table) with verify/restore and forward migration;
provider catalog with an honest capability matrix; OpenAI and Anthropic
per-key usage/cost sync, GitHub billing, and Stripe Events (admin key,
honest attribution); cost estimation kept separate from provider-reported
cost; budgets and 20 explainable suspicious-activity rules; local repository
secret scanning (staged / working tree / history incl. full history) with a
pre-commit hook and suppressions; `.env` governance (discover, import,
example, drift, guided migration, reauth-gated export); destinations + review
able sync plans with rollback; durable, reauthenticated credential rotation;
temporary local access grants with session listing/termination; documentation
watching with intervals and history; native desktop notifications and
optional webhook channels. The desktop app and CLI share one Rust core and one
SQLite vault.

## Known limitations (honest)

- **Product**: no project templates / stack learning; cost estimation covers a
  small bundled price table (tokens only); one provider org per vault.
- **Provider**: per-key usage exists only where the official API supports it
  (OpenAI, Anthropic); GitHub/Stripe are account-level; no provider issues
  short-lived credentials via API; no provider offers a documented per-key
  scope edit (changes route through the dashboard or the rotation workflow).
  None of this is faked — it is labeled everywhere.
- **Destinations**: AWS/GitHub/Vercel network paths are fixture-tested, not yet
  exercised against live accounts; AWS delete and Vault/Doppler/1Password /
  Windows-Linux keychains are not implemented (labeled). See
  [DESTINATION_SUPPORT.md](DESTINATION_SUPPORT.md).
- **Security**: metadata (names, providers, notes) is stored unencrypted next
  to the encrypted values — treat the data directory as sensitive. Local-first
  cannot defend against malware running as you or an unlocked machine. See the
  threat model for the full list, including documented residuals.
- **Packaging/signing**: installers are **unsigned and un-notarized**; you will
  see OS warnings on first launch (see [INSTALL.md](INSTALL.md)). Only macOS
  arm64 artifacts were built locally at release time; the other platforms come
  from CI and should be smoke-tested from the draft release before publishing.

## Verify your download

Each release ships per-artifact `.sha256` files and a combined
`SHA256SUMS.txt`. Verify before running:

```bash
shasum -a 256 -c SHA256SUMS.txt      # macOS/Linux
certutil -hashfile <file> SHA256     # Windows
```

## Reporting a vulnerability

Privately, via GitHub Security Advisories — see [SECURITY.md](../SECURITY.md).
Use only fake credentials in reproductions.
