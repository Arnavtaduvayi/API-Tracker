# Tethra Rebrand Plan (API Tracker → Tethra)

- **New product name:** Tethra (exact capitalization: `Tethra`)
- **Official domain branding:** UseTethra.com
- **Scope:** compatibility-safe rebrand for the macOS private-alpha release
  on branch `release/tethra-macos-private-alpha`.
- **Non-goals:** UI redesign (owned by the cofounder on `eesh-ui`), GitHub
  repository/organization rename, signing-identity changes, any change that
  makes an existing API Tracker vault unreadable or invisible.

## Guiding rule

The *visible product* becomes Tethra; *persisted and cryptographic
identifiers* stay `api-tracker` until a separately planned migration.
Renaming any identifier that is baked into ciphertext AADs, on-disk formats,
user shell environments, installed git hooks, or OS keychains would strand
or destroy existing user data — every such identifier is preserved verbatim
and listed below.

## Identifier classification (§7.6)

### Renamed safely (user-facing, no persistence impact)

| Identifier | Old | New | Where |
|---|---|---|---|
| Tauri product name | `API Tracker` | `Tethra` | `tauri.conf.json` `productName` → `Tethra.app`, Finder name, DMG volume |
| Window title | `API Tracker` | `Tethra` | `tauri.conf.json` window `title`, `index.html <title>` |
| Native notification titles | `API Tracker` | `Tethra` | `App.tsx`, `AlertsView.tsx` |
| UI prose / dialogs / errors | `API Tracker` | `Tethra` | desktop components, core error hints, CLI messages |
| CLI help header (clap `name`) | `api-tracker` | `tethra` | `apps/cli/src/main.rs` (both binaries print `tethra` usage) |
| Preferred CLI binary | — | `tethra` (new `[[bin]]`, same `src/main.rs`) | `apps/cli/Cargo.toml` |
| Documented command in docs/help text | `api-tracker …` | `tethra …` | README, docs, in-app command hints |
| npm package name | `api-tracker-desktop-ui` | `tethra-desktop-ui` | private package; lockfile root regenerated with the lockfile-preserving flow |
| HTTP User-Agents | `api-tracker/0.1 (+local)` etc. | `tethra/0.1 (+local)` etc. | `http.rs`, `docwatch.rs`, `connectors.rs`, `destinations.rs` (cosmetic request header) |
| Release workflow branding | `API Tracker <tag> (alpha)`, `api-tracker-<target>` archives | `Tethra <tag> (alpha)`, `tethra-<target>` archives (containing both binaries) | `.github/workflows/release.yml` (not triggered by this release — no tag pushed) |
| New env vars (preferred) | — | `TETHRA_*` full set | see compatibility matrix |
| Desktop backend panic string | "API Tracker desktop app" | "Tethra desktop app" | `src-tauri/src/main.rs` |
| Pre-commit hook body (new installs) | invokes `api-tracker` | prefers `tethra`, falls back to `api-tracker` | `hooks.rs` (sentinels unchanged) |

### Preserved for compatibility (do not change — data/scripting continuity)

| Identifier | Value | Why it must not change |
|---|---|---|
| Ciphertext AAD / HKDF labels | `api-tracker:v1:…` (12 labels, `crypto.rs`) | changing any label makes every existing vault, backup, and session undecryptable |
| Backup format marker | `api-tracker-backup` (`backup.rs:46`) | old backups must stay restorable; new backups must stay restorable by old builds where schema allows |
| Data directory name | `api-tracker` (`vault.rs:83`) | existing vaults must be found; no migration this release (macOS `~/Library/Application Support/api-tracker/`) |
| DB / session filenames | `vault.db`, `session.json` | brand-free; shared by old and new builds |
| macOS bundle identifier | `dev.api-tracker.desktop` | see §Bundle identifier below |
| Legacy env vars | `API_TRACKER_*` (all) | user scripts and CI keep working; read as fallback, still scrubbed from injected children |
| Legacy CLI binary | `api-tracker` | compatibility entry point; same code as `tethra` |
| Hook sentinels | `# >>> api-tracker pre-commit hook >>>` / `<<<` | installed hooks in user repos are recognized, upgraded, and removable only via these markers |
| Keychain/credential-manager defaults | account/service `api-tracker`, Windows target `api-tracker/{name}` | existing stored destination secrets stay reachable |
| Temp-file infix + orphan sweep | `.api-tracker-tmp-` | crash-cleanup must still match temp files written by old builds |
| Webhook payload `source` | `api-tracker` | user webhook receivers may filter on it |
| Rotation provider-key prefix | `api-tracker-rotation-<id>` | provider-side artifacts already exist under this prefix |
| `--print-export` legacy line | `export API_TRACKER_SESSION="…"` still printed (first) | old scripts parse this exact line; the `TETHRA_SESSION` line is printed after it |

### Deferred with explanation

| Identifier | Current | Why deferred |
|---|---|---|
| Cargo package/crate names | `api-tracker-core`, `api-tracker-cli`, `api-tracker-desktop` | internal identifiers; renaming churns 421 `api_tracker_core::` references, CI `-p` flags, and audit cross-references for zero user-visible benefit; safe to do later as a mechanical change |
| GitHub repository / remotes | `Arnavtaduvayi/API-Tracker` | explicitly out of scope (not separately authorized) |
| Data directory rename to `tethra` | `api-tracker` | requires a migration with conflict handling; unnecessary risk for this release — `TETHRA_DIR`/`API_TRACKER_DIR` overrides and the legacy default keep old and new builds on the same vault |
| Bundle identifier | `dev.api-tracker.desktop` | see below |
| Linux/Windows packaging identity (`AppImage`, apt package name) | `api-tracker` | out of scope for a macOS-only private alpha; CI-built only |
| App icon | existing approved icon set | no Tethra-specific approved icon exists in the repository; inventing a logo is out of scope |

## Bundle identifier decision (§7.7)

`dev.api-tracker.desktop` is **preserved** for this release. Changing it
would make macOS treat Tethra as an unrelated application: notification
authorization, saved-app-state, privacy/TCC grants, and default-app
associations are all keyed by bundle id, and an upgrade-in-place from the
existing installed app would become a second app instead. There is no
signing identity available to smooth such a migration. The visible product
name is fully controlled by `productName`/`CFBundleName`, which do change to
Tethra. Revisit alongside a future signed release.

## CLI strategy (§7.3)

`apps/cli/Cargo.toml` gains a second `[[bin]] name = "tethra"`. The program
itself moved to `apps/cli/src/lib.rs`; both entry points (`src/main.rs` for
`tethra`, `src/legacy_bin.rs` for `api-tracker`) are one-line wrappers over
`run_cli()`, so the two commands run identical code and cannot drift apart.
(Pointing two `[[bin]]` targets at one source file also works but makes cargo
warn on every build.) Help and version branding is derived from argv[0]
against a fixed allowlist of the two shipped names — each command reports
itself, and an unrecognized argv[0] falls back to `tethra` rather than being
echoed into rendered output. No per-invocation deprecation banner is
emitted — machine-readable output (`--json`, `--print-export`) is unchanged
except that `--print-export` additionally prints the `TETHRA_SESSION` export
line after the legacy line. Docs and in-app hints reference `tethra`;
`api-tracker` remains fully supported and tested.

## Environment variables (§7.4)

Preferred `TETHRA_*` names are introduced for every user-facing variable,
with `API_TRACKER_*` preserved as fallback. Precedence: the `TETHRA_*`
variable wins whenever it is present (even if set to the empty string —
presence is authoritative, preserving the existing "empty means unset/none"
semantics per variable); the legacy variable is used only when the preferred
one is absent. If `TETHRA_DIR` and `API_TRACKER_DIR` are both present with
*different* values, a warning is printed to stderr and `TETHRA_DIR` is used —
the two locations are never combined. Secret values are never printed.
Both prefixes are scrubbed (deny-by-default, case-insensitive on Windows)
from any child process spawned by `tethra run`, with the same two-entry
child-safe allowlist per prefix (`*_DIR`, `*_INSECURE_FAST_KDF`). Full table
in `TETHRA_COMPATIBILITY_MATRIX.md`.

## Existing-user data (§7.5)

No storage identifier changes, therefore: existing vaults are found exactly
as before (same directory, same filenames), nothing is moved, copied, or
migrated, no empty new vault can shadow an old one, and backups/hooks/
keychain items keep working. A migration failure mode does not exist because
there is no migration. Verified by the compatibility test matrix in
`TETHRA_MIGRATION_GUIDE.md` §Testing.

## Historical documents

Audit reports, remediation ledgers, evidence logs, and the 2026-07-19 manual
test run keep their original "API Tracker" naming. Living docs that carry a
verified-baseline stamp (`docs/UI_MAP.md`, `docs/MANUAL_UI_TEST_PLAN.md`,
`docs/MANUAL_TEST_DATA.md`) receive a banner: "API Tracker was renamed
Tethra after this report was produced." — their baseline content is not
rewritten.
