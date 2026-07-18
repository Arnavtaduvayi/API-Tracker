# ADR 0008: Provider catalog, scanning, monitoring, and documentation watching

Status: accepted (2026-07-18)

This records the design of milestone 2, which extends (does not rewrite) the
milestone-1 vault. New core modules: `providers` (rewritten), `scanner`,
`gitrepo`, `hooks`, `alerts`, `monitor`, `docwatch`. New database migration
v2 adds `scan_suppressions`, `alerts`, and `doc_watches`.

## Provider manifests

Providers are TOML files under `provider-manifests/`, embedded at compile
time via `include_str!` and parsed+validated by a unit test. This satisfies
"version-controlled provider manifests" while guaranteeing the catalog is
always available offline with no runtime file dependency, and makes adding a
provider a matter of adding one reviewed file.

The capability matrix is modelled as a primary `SupportLevel`
(`implemented` / `supported_not_implemented` / `unsupported` / `manual_only`)
plus two orthogonal facts: `requires_admin_credential` and an `attribution`
granularity (`account` / `provider_project` / `exact_credential`). This lets
us state, honestly and precisely, e.g. that OpenAI usage can attribute token
counts per key but only reports dollar cost at project level. **No capability
is `implemented`** in this milestone — provider connectors are future work
(ADR 0007's successor). Capability values were verified against official
provider documentation before encoding.

`env_vars` lists **secret-bearing** variables only (used both for display and
scanner detection). Non-secret variables (org ids, publishable keys, URLs)
are deliberately excluded to avoid false positives.

## Scanner

`scanner::scan_text` is pure and offline. It combines three signals: provider
key regexes from the manifests (high/medium), assignments to known secret
env-var names (medium), and calibrated Shannon-entropy detection gated on a
secret-like variable name (low). Overlapping regex matches are de-duplicated
keeping the most specific/highest-confidence rule. Findings keep the raw
value in a `SecretString` marked `#[serde(skip)]`, so a finding can be matched
against the vault in-process yet never serializes the secret; it exposes only
a redacted preview and a non-secret `suppression_key`.

Vault matching, suppression, and possibly-exposed marking live in the vault
(it owns the keyed fingerprint and the database). Matching a finding reuses
the existing reuse-fingerprint machinery, so a scanned secret is identified as
the exact stored credential and every project referencing it.

## Git integration and hooks

`gitrepo` shells out to the user's `git` (no libgit2 dependency): working
tree (via a filtered directory walk), staged blobs, and history diffs
(`git log -p -U0`, parsed to per-file added lines with real line numbers).
The pre-commit hook writes a sentinel-delimited block into
`.git/hooks/pre-commit`; it refuses to clobber a foreign hook unless forced
(then appends, preserving it) and removes only its own block. The hook runs
`api-tracker scan --staged --hook`, which uses a **no-unlock** path: it reads
suppressions (unencrypted, no secret material) and runs pattern detection
without the master password, so committing never prompts. It blocks only on
high-confidence findings; `git commit --no-verify` bypasses as usual.

## Alerts and monitor

`alerts` stores a create→acknowledge→resolve lifecycle with a `dedup_key`
(one open alert per condition) and auto-resolution when a condition clears.
`monitor` maps the existing status/reuse evidence to alerts (expired,
expiring-soon, stale, unused, reuse-across-projects, production-in-development,
possible-exposure). The "scheduler" is a `run_monitor` function both frontends
call — on demand in the CLI, on a timer in the desktop app — rather than a
background daemon, keeping it simple and battery-friendly.

## Documentation watcher

`docwatch` performs conditional HTTP GETs (`If-None-Match` / `If-Modified-Since`),
hashes the body with BLAKE3, and stores only validators, the hash, and
timestamps — never the page content. The transport is behind the `DocFetcher`
trait: the real `HttpFetcher` uses `ureq` (blocking, rustls, 20s timeout, a
descriptive User-Agent, 8 MiB cap); tests use a scripted `MockFetcher`, so the
entire change-detection state machine is verified offline. A detected change
raises a `documentation_changed` alert; the UI/CLI state clearly that a page
change does not necessarily mean a breaking API change.

## Security notes

- No secret value ever leaves a finding, alert, suppression, or log; tests
  assert this at every layer.
- Suppression keys and doc-watch state are non-secret, so the pre-commit hook
  can read them without unlocking the vault.
- The docs watcher is the first outbound network component; it only contacts
  explicit user-selected URLs, sends conditional requests, caps the body, and
  handles offline/error by preserving prior state. It does not crawl, follow
  links, or bypass access controls.
- Marking a credential possibly-exposed on a scan match is metadata only; the
  scanner never modifies files, rewrites history, or revokes/rotates keys.

## Alternatives considered

- **libgit2 (`git2` crate)** instead of shelling out: rejected — a large C
  dependency in a security-sensitive tool for functionality the `git` binary
  already provides locally.
- **Runtime-loaded manifests** from a directory: rejected for now — embedding
  keeps the catalog dependency-free and validated at build time; a
  user-extensible directory can be layered on later without changing the type.
- **`reqwest`/async** for the watcher: rejected — `ureq` blocking fits the
  command/timer model with far fewer dependencies and no async runtime.
