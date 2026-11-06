# Increment 09: Desktop, devices and the in-process node

**Mode:** O (orchestrator plus two parallel subagents: Rust commands, React UI) · **Size:** M · **Prerequisites:** 08 done

## Goal

Desktop users can do the whole device workflow without the CLI:
- create a mesh;
- pair a device (show or enter an invite);
- see devices and their health;
- remove a device;
- run the mesh node while Tethra is open.

The node runs **in-process on a thread**, stops on lock and exit, and never hands keys
to a child process (D13).

## Read first

- DESIGN §D4 (reauth in core), §D5 (key lifetime), §D13 ("Who runs the node") and §D20.
- `apps/desktop/src-tauri/src/main.rs`:
  - 34-53: `ErrDto` / `CmdResult`;
  - 91-100: `AppState`;
  - 154-199: `with_vault*` and auto-lock;
  - 4276-4297: `foreground_gateway` spawn, for contrast;
  - 4366-4381: stop;
  - 4751-4770+: `generate_handler!`;
  - 4992-5006: exit.
- `crates/core/tests/tauri_command_authz.rs` (1-23 and the test patterns) and `docs/remediation-phase-2/tauri_command_inventory.json`.
- `apps/desktop/src/api.ts` (`call<T>()` at 222, `api` at 236+), `types.ts`, `App.tsx` (`View` union 64-94, `NAV_GROUPS` 102-128, `ADVANCED_SETTINGS` 156-185).
- `components/ReauthDialog.tsx`, `ConfirmDialog.tsx`, `GatewayView.tsx` (the closest existing "service with status" view) and `SettingsView.tsx`, plus 2-3 existing `*.test.tsx` files and `src/test/setup.ts`.
- `docs/mesh/USER_GUIDE.md`.

## Scope (build all of this)

### Rust: `apps/desktop/src-tauri/src/mesh_cmds.rs` (new module; main.rs is already 5000+ lines)

Tauri commands. Each is a thin wrapper over core, with **no business logic**:
- `mesh_status`
- `mesh_init(name)`
- `mesh_invite_create(master_password, ttl_minutes)`
- `mesh_join(invite, name)`
- `mesh_devices`
- `mesh_device_rename(name)`
- `mesh_device_remove(master_password, device_id)`
- `mesh_leave(master_password)`
- `mesh_peers_list`, `mesh_peer_add(addr)`, `mesh_peer_remove(addr)`
- `mesh_replicate_now(peer?)`
- `mesh_doctor`
- `mesh_node_get_settings` / `mesh_node_set_settings({ run_while_open, listen: [addr], all_interfaces, discover })`.
  These are local-only settings in `mesh_meta`. Setting `all_interfaces` or `discover`
  requires reauth, because each opens a LAN surface. Enforce that in core.

**Node lifecycle** in `AppState` (a new `mesh_node: Mutex<Option<NodeHandle>>`):
- **Starts** after unlock if `run_while_open` is set, and when the setting is turned on.
- **Stops** on lock (every lock path, including auto-lock in `with_vault*`), on
  `run_while_open` off, and on exit (hook in alongside `stop_foreground_gateway` at
  4366-4381 and 4992-5006).
- Uses `StopCondition::LockSignal` (05).
- Its errors surface in `mesh_status` and never crash the app.

Register the commands in `generate_handler!`, and add `docs/remediation-phase-2/tauri_command_inventory.json`
rows that classify each one's enforcement. The inventory is stale at 137 commands; add
the mesh rows and note that in a comment field. Don't attempt a full re-inventory.

Authz tests for every reauth-gated core method used here go in
`crates/core/tests/tauri_command_authz.rs`:
- wrong password → `WrongPassword`;
- the right one succeeds;
- no secret appears in the error;
- `all_interfaces` / `discover` require reauth.

### React: `apps/desktop/src/components/DevicesView.tsx` (+ small subcomponents)

Add a nav entry. Prefer `NAV_GROUPS` → "Devices", or under Settings if the IA review
says so.

**Not in a mesh:** explain in two or three plain sentences what the mesh does and does
not do, linking to the user guide. Then offer **Create mesh** (name) or **Join a mesh**
(paste an invite).

**In a mesh:**
- **This device:** name (rename), id (short), node running or stopped (toggle
  `run_while_open`), and listen addresses (edit; the warnings below apply).
- **Devices list:** name, status (last exchange, stale or removed badges), lag, and a
  **Remove** action through `ConfirmDialog`, then `ReauthDialog`.
- **Pair a device:** `ReauthDialog` → create the invite → show the invite string **once**
  with copy-to-clipboard, an expiry countdown and the "treat this like a password for 10
  minutes" warning. Closing the dialog drops it from React state.
- **Peers:** manual addresses (add or remove), backoff state.
- **Health:** the `doctor` summary, with a "Replicate now" button.
- **Leave mesh:** confirm, then reauth.

**Rules:**
- **Plain, accessible UI** (CLAUDE.md priorities): no new design system. Reuse the
  existing card styles.
- **Never render key material.** The invite string is the only bearer secret shown, and
  only once.
- **LAN warnings:** enabling all interfaces or discovery shows a clear warning about LAN
  exposure, and requires reauth.

Add `api.ts` methods and `types.ts` types for every command.

## Execution workflow (O)

1. **Contract (you). Commit before spawning.**
   - Write `mesh_cmds.rs` with every command's **signature** and DTO structs, with bodies
     returning a typed `ErrDto { code: "NotImplementedYet" }`. These stubs exist only for
     the duration of this increment and are replaced before it ends; none may remain at
     the final commit.
   - Add the matching `types.ts` interfaces and `api.ts` method stubs.
   - Name the React component files and their props.
   - Commit: `chore(desktop): mesh command contract for increment 09`.
2. **Spawn two subagents in parallel** (`subagent_type: general-purpose`, one message,
   two Agent calls):
   - **Subagent A (Rust)** owns:
     - `apps/desktop/src-tauri/src/mesh_cmds.rs`;
     - the `AppState` additions and the lifecycle hooks in `main.rs`. Allow main.rs edits
       only inside clearly delimited regions: the `AppState` struct, `generate_handler!`,
       the lock paths and the exit hook;
     - `crates/core/tests/tauri_command_authz.rs` (additions);
     - any core reauth helpers needed for the settings;
     - `tauri_command_inventory.json`.

     Its commands are `cargo build --release -p api-tracker-cli && bash scripts/bundle_cli.sh`
     once, then `cargo clippy -p api-tracker-desktop -- -D warnings` and
     `API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --test tauri_command_authz`.
   - **Subagent B (React)** owns:
     - `apps/desktop/src/components/DevicesView.tsx` and its subcomponents;
     - their `*.test.tsx` files;
     - the nav wiring in `App.tsx` (only the `View` union, the `NAV_GROUPS` entry and the
       route switch);
     - the `api.ts`/`types.ts` bodies **only if** the contract needs fixes, which it must
       report.

     Its commands are
     `cd apps/desktop && npm ci --cache "$(mktemp -d)" && npm run format:check && npm run lint && npm run typecheck && npm test`.
     It mocks `api` in tests and needs no Rust build. It must not run cargo.
   - **Both get:** the contract location, DESIGN §D13/§D20, `docs/mesh/USER_GUIDE.md`,
     and the instruction "do not commit, do not touch git, do not edit files outside your
     list, report what you changed and any contract problems".
3. **Integrate (you).**
   - Run the full suite, including the desktop build:
     `npm run build`, then `cargo clippy -p api-tracker-desktop -- -D warnings`.
   - Replace any remaining stub. A `grep -n NotImplementedYet` must return nothing.
   - Do a manual run with `TETHRA_DIR` set to a temp dir:
     `cd apps/desktop && TETHRA_DIR="$(mktemp -d)/tethra" TETHRA_INSECURE_FAST_KDF=1 npx tauri dev`.
     Then:
     1. Create a mesh, set listen to `127.0.0.1:0`, and start the node.
     2. In a second terminal, run the CLI with **another** temp `TETHRA_DIR`: `mesh join` with the invite from the UI.
     3. Watch the device appear.
     4. Remove it.
     5. Lock the app and verify the node stopped (`mesh status` from the CLI against the
        app's data dir says not running).

     **Never** run `tauri dev` without `TETHRA_DIR`, because it opens the real vault.
   - Commit and push.

## Tests to write

- **Rust:**
  - authz tests as listed above;
  - a lifecycle unit test: start on unlock with `run_while_open`, stop on lock, stop on
    exit, no start when locked. Test it at the `NodeHandle` level with a fake node
    factory if the Tauri runtime isn't testable.
- **Vitest:**
  - not-in-mesh vs in-mesh rendering;
  - the pair flow (reauth → invite shown once → dialog closed → invite gone from the
    DOM);
  - remove requires confirm and then reauth;
  - LAN-exposure settings require reauth and show the warning;
  - error display uses `ErrDto.message` without leaking anything;
  - stale and removed badges.

## Acceptance criteria

- [ ] Every Devices workflow works in the desktop app end to end. The manual run above was performed and is described in STATUS.md.
- [ ] The node is in-process, stops on lock and exit, and keys are never passed to a child process.
- [ ] Reauth is enforced in core and proven by `tauri_command_authz` tests. The inventory is updated.
- [ ] No `NotImplementedYet` remains. Frontend and desktop checks are green, and CI's `desktop` and `frontend` jobs pass.

## Verification commands

```bash
(cd apps/desktop && npm ci --cache "$(mktemp -d)" && npm run format:check && npm run lint && npm run typecheck && npm test && npm run build)
cargo clippy -p api-tracker-desktop -- -D warnings
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --test tauri_command_authz
grep -rn "NotImplementedYet" apps/desktop && exit 1 || true
# plus the full README §3 suite
```

## Docs to update

- `docs/mesh/USER_GUIDE.md`: a desktop section.
- `docs/MANUAL_UI_TEST_PLAN.md`: add a Devices section. Also fix its `TETHRA_DATA_DIR`
  typo to `TETHRA_DIR` (line 2851) while you're there.
- `CHANGELOG.md`.

## Handoff checklist

- [ ] STATUS.md row 09 `done`. Record what each subagent reported and any contract changes.
- [ ] Handoff notes: the component and API patterns that 10 should reuse.
