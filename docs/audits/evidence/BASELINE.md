# Deep Technical Audit — Baseline Record

## Commit / worktree
- Commit: `7d81090a1068476291546963e68ca8c7de1a7145` (tag/short 7d81090) — verified matches requested baseline.
- Branch: `audit/deep-pressure-test`
- Worktree: `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-deep-audit` (audit worktree; main worktree at .../API-Tracker on 7d81090; third worktree API-Tracker-ui-map on audit/ui-map)
- Remote: origin → https://github.com/Arnavtaduvayi/API-Tracker (fetch+push)
- Working tree: CLEAN at start.

## Toolchain / platform
- OS: macOS 26.5 (build 25F71), Darwin 25.5.0, arm64 (Apple Silicon T6050)
- rustc/cargo: 1.96.1 (2026-06-26); also installed: 1.97.0 toolchain (CI uses 1.97.0 for clippy — memory note)
- node: v24.13.0, npm: 11.6.2 (no pnpm/yarn)
- sqlite3 CLI: 3.51.0 (rusqlite uses bundled SQLite)
- cargo-tauri: NOT installed locally (desktop bundling not runnable here)

## Env vars affecting tests
- `API_TRACKER_INSECURE_FAST_KDF=1` (debug-only) switches Argon2id to weak params for test speed; release ignores it.
- No API_TRACKER_* secrets set in environment. TMPDIR under /var/folders (macOS default).

## Size
- Tracked files: 217
- Rust: 84 .rs files, ~45,857 LOC (incl. tests)
- Frontend: ~9,413 LOC TS/TSX
- Biggest files: vault.rs (8520), destinations.rs (2153), main.rs desktop (2168), connectors.rs (1725), pricing.rs (1519), backup.rs (919), db.rs (815), envgov.rs (792), openai.rs (751).

## Security-critical surfaces (inventory)
- forbid(unsafe_code) in core/lib.rs; zero unsafe blocks in any production src. Windows keyring via audited wrapper crate.
- Crypto: argon2 0.5.3, chacha20poly1305 0.11.0 (XChaCha20-Poly1305), blake3, crypto_box (sealed box), getrandom 0.4.3, subtle, zeroize, sha2, hmac. CRYPTO_VERSION=1. Argon2id 64MiB/t=3/p=1.
- DB: rusqlite 0.40.1 bundled.
- HTTP: ureq 3.3.0 (blocking) behind mockable HttpClient trait; docwatch uses ureq::Agent directly.
- Desktop: tauri 2, arboard (clipboard), tauri-plugin-opener, tauri-plugin-notification.
- Tauri commands: 136 (#[tauri::command]).
- Process launch: git (envgov, hooks, gitrepo), kill/taskkill/ps (inject, access_cmd), arbitrary program (run_cmd, destinations env-file exec).
