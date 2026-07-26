# Tethra Compatibility Matrix

Status of every identifier surface after the API Tracker → Tethra rebrand
(`release/tethra-macos-private-alpha`). "Preserved" means deliberately
unchanged for data/scripting continuity; see
`TETHRA_REBRAND_PLAN.md` for rationale and `TETHRA_MIGRATION_GUIDE.md`
for user-facing behavior.

| Surface | Old | New / status | Compatibility behavior |
|---|---|---|---|
| App display name | API Tracker | **Tethra** | cosmetic; same app identity |
| macOS app bundle | `API Tracker.app` | **`Tethra.app`** | new bundle name, same bundle identifier |
| Window title | API Tracker | **Tethra** | — |
| Native notification title | API Tracker | **Tethra** | — |
| DMG / volume name | API Tracker | **Tethra** | tauri `productName` drives both |
| Bundle identifier | `dev.api-tracker.desktop` | **preserved** | keeps notification permission, saved state, upgrade-in-place |
| CLI commands | `api-tracker` | **`tethra` preferred; `api-tracker` kept** | two `[[bin]]` targets over one `run_cli()` library; identical behavior and machine output; help usage line follows the invoked name |
| CLI help/version branding | api-tracker | argv0-derived: `tethra` from the preferred binary, `api-tracker` from the legacy one (help **and** version) | `api-tracker --version` still prints `api-tracker <version>`, so old parsers are unaffected; an unrecognized argv[0] falls back to `tethra` and is never echoed |
| Env vars | `API_TRACKER_*` | **`TETHRA_*` preferred; legacy honored** | preferred wins when both set; DIR conflict warns on stderr and uses `TETHRA_DIR`; both prefixes scrubbed from `run` children (allowlist: `*_DIR`, `*_INSECURE_FAST_KDF`) |
| `unlock --print-export` | one legacy line | **two lines: legacy first, then `TETHRA_SESSION`** | old line-parsers and `eval` both keep working; a stale session var falls back to a set password var instead of wedging |
| Data directory | `…/api-tracker/` | **preserved** | existing vaults found unchanged; no migration, no new dir |
| DB filename | `vault.db` | preserved (brand-free) | shared by old/new builds concurrently (WAL) |
| Session file | `session.json` | preserved (brand-free) | sessions survive the upgrade |
| Ciphertext AAD labels | `api-tracker:v1:…` | **preserved (hard constraint)** | all existing vaults/backups/sessions decrypt |
| Backup format marker | `api-tracker-backup` | **preserved** | restore works in both directions |
| Backup filenames | user-chosen | docs suggest `tethra-backup.json` | no enforced scheme; old names fine |
| Git hook sentinels | `# >>> api-tracker pre-commit hook >>>` | **preserved** | old hooks recognized/upgradable/removable by new builds |
| Git hook body (new installs) | invokes `api-tracker` | prefers `tethra`, falls back to `api-tracker` | works whichever binary is on PATH; old installed hooks unmodified until reinstall |
| Keychain (macOS) defaults | service/account `api-tracker` | **preserved** | existing destination secrets reachable |
| Windows Credential Manager | target `api-tracker/{name}`, account `api-tracker` | **preserved** | same |
| Temp-file infix | `.api-tracker-tmp-` | **preserved** | crash-cleanup still matches old temp files |
| Webhook payload `source` | `api-tracker` | **preserved** | receiver filters keep matching |
| Rotation provider-key prefix | `api-tracker-rotation-` | **preserved** | provider-side artifact continuity |
| HTTP User-Agents | `api-tracker…` | `tethra…` | cosmetic request header |
| Cargo crates | `api-tracker-{core,cli,desktop}` | **deferred** | internal identifiers; `cargo build -p api-tracker-cli` etc. unchanged |
| npm package name | `api-tracker-desktop-ui` | `tethra-desktop-ui` | private package; lockfile root updated, dependency tree untouched |
| Scripts | `scripts/smoke.sh`, `demo.sh` | invoke the `tethra` binary; legacy env vars still exercised | smoke doubles as a compat test (new binary + legacy vars) |
| CI (`ci.yml`) | unchanged | unchanged | crate names and legacy env var still valid; exercises the legacy path continuously |
| Release workflow | `api-tracker-<target>` archives, "API Tracker …" release name | `tethra-<target>` archives containing **both** binaries, "Tethra …" | not triggered by this release (no tag pushed) |
| GitHub repo / remotes | `Arnavtaduvayi/API-Tracker` | **unchanged (out of scope)** | all links remain valid |
| Docs | API Tracker | living docs rebranded; historical reports and ADRs keep their original naming (living docs carrying a verified-baseline stamp get a correcting banner) | see plan §Historical documents |
| Packaged app behavior | — | verified in `docs/release/TETHRA_MACOS_PACKAGING_RESULTS.md` | fresh vault, legacy vault, backup/restore, reauth, CSP, links |

## Test coverage for this matrix

- `apps/cli/tests/tethra_compat.rs` — 15 tests: both binaries on one vault
  (both directions), wrong password under both flavors, env precedence
  (preferred wins, legacy fallback, empty-preferred authoritative), DIR
  conflict warning + no-warning case, dual export lines + both session vars,
  argv0 help naming, argv0 **version** naming (each command reports its own
  name) plus the unrecognized-argv0 fallback, dual-prefix child scrub,
  stale-session password fallback (with wrong-password and no-password
  negative cases).
- `crates/core/src/inject.rs` unit tests — dual-prefix scrub semantics on
  Unix (case-sensitive) and Windows (case-insensitive), allowlists.
- `crates/core/src/envcompat.rs` unit tests — pair resolution rules.
- `crates/core/tests/gscan_hooks.rs` — legacy-named binary fallback in the
  new hook; legacy-format installed hook recognized, upgraded in place, and
  removed cleanly.
- `apps/cli/tests/run_env_scrub.rs`, `apps/cli/tests/cli.rs` — legacy-path
  regression suites, updated only where they parse the dual export output.
- `scripts/smoke.sh` — end-to-end: `tethra` binary driven entirely by
  legacy `API_TRACKER_*` variables.
