# Increment 10: Desktop shared projects, cross-device usage and caps

**Mode:** O (orchestrator plus two parallel subagents, the same pattern as 09) · **Size:** M · **Prerequisites:** 09 done

## Goal

Desktop users can share and bind projects, see honest cross-device usage on each
project, and create and manage spend caps, including the reauth-gated local enforcement
toggle. All of it reuses core logic, with no business logic in TypeScript.

## Read first

- DESIGN §D11, §D14 (the views and the honesty labels), §D15 and §D19 (MESH-SI-9/11/13).
- ADR 0032.
- `apps/desktop/src/components/ProjectDetail.tsx`, `ProjectActivity.tsx`, `UsageView.tsx`, `ActivityChart.tsx` (how charts and labels are done today), `DevicesView.tsx` (from 09) and `utils.ts`/`usage.ts`. Note the money formatting there.
- `docs/projects-first/COST_ESTIMATION.md` (the honest-cost language the UI already uses).
- The STATUS.md handoff notes for 08 and 09.

## Scope (build all of this)

### Rust: `mesh_cmds.rs` additions

Thin wrappers again:
- `mesh_projects_list`
- `mesh_project_share(local_project_id)`
- `mesh_project_bind(mesh_project_id, local_project_id)`
- `mesh_project_unbind(local_project_id)`
- `mesh_project_rename`, `mesh_project_archive`
- `mesh_project_merge(a, b)`, which needs confirmation in the UI
- `mesh_usage_report(filter)`
- `mesh_caps_list`
- `mesh_cap_create(mesh_project_id, monthly_micros)`
- `mesh_cap_raise(cap, micros)`, `mesh_cap_lower(cap, micros)`
- `mesh_cap_rights(cap)`
- `mesh_cap_reclaim(cap)`
- `mesh_cap_enforce(master_password, cap | all, on)` (reauth in core)

Add authz tests for `mesh_cap_enforce`, and rows in the inventory.

### React

- **`ProjectDetail`** gets a "Devices" panel:
  - not shared → a **Share with my devices** button, with a sentence on exactly what
    replicates (counters, not requests);
  - shared → the mesh project name, other devices publishing, Unbind;
  - a project shared from another device but not bound here appears in a **"Available
    from your devices"** list (on the Devices page or the projects list) with **Bind
    to…** (choose a local project, or create a new one through the existing project
    form).
  - **Never automatic.**
- **`MeshUsageCard`** on the project page and the Usage page:
  - a per-device table: device, requests, tokens, estimated cost, unpriced/unextracted
    counts, and "as of";
  - a total row labelled **"Estimated, gateway-observed, across N devices (M stale)"**;
  - stale and removed badges;
  - "No data from <device>" rows.
  - **Never** mix it with provider-reported cost figures. Keep it a separate card with
    separate wording (SI-19).
- **`CapsPanel`** on the project page when the project is shared:
  - Create a cap (monthly USD).
  - Show it: target, used across devices, this device's available amount, pending
    decrease, frozen, and a per-device rights table.
  - Raise. On a non-owner, an override confirmation explains what it means.
  - Lower, with confirmation.
  - Reclaim (owner only).
  - The **Enforce on this device** toggle uses `ReauthDialog` and explains the 403
    behaviour, bounded overshoot and the "self-limit, not a security boundary" point.
  - When `inactive_reason` is set, show a warning: "Enforcement inactive: …".
- **Alerts:** confirm the mesh cap alerts from 07 render in the existing Alerts view
  with their labels. Adjust copy only if they don't.

## Execution workflow (O)

The same workflow as 09 §"Execution workflow":
1. You commit the contract: command signatures, DTOs and TS types.
2. Subagent A owns Rust (`mesh_cmds.rs` additions, authz tests, inventory).
3. Subagent B owns React: `ProjectDetail` changes in delimited regions, the new
   `MeshUsageCard.tsx` and `CapsPanel.tsx`, the "Available from your devices" list,
   and the tests.
4. You integrate and do the manual run.

Point both subagents at this file and at 09's workflow section, and keep the same
rules: no commits, file ownership, no cargo for the React subagent.

**The manual run, using temp `TETHRA_DIR`s only:**
1. The desktop app (with a temp dir) and a CLI node (with another temp dir) are paired.
2. Share a project in the app and bind it from the CLI.
3. Seed usage on the CLI device using the same mechanism smoke uses (06).
4. Watch it appear per-device in the app.
5. Create a cap in the app, exhaust rights on the CLI device's **foreground** gateway,
   and see the 403 there. The app shows that device's used amount rising after the
   exchange.

## Tests to write

- **Rust:** authz tests for enforcement.
- **Vitest:**
  - share and bind flows, including never-automatic: rendering doesn't trigger a bind;
  - usage card labels: stale, removed, no-data, unpriced counts shown, total wording;
  - no provider cost in the card;
  - cap create, raise and override confirmation text, lower confirmation;
  - the enforce toggle requires reauth and shows the explanation;
  - the inactive-reason warning;
  - frozen-cap state;
  - merge requires confirmation and shows the refusal message when both projects have
    caps.

## Acceptance criteria

- [ ] Every 06/07/08 capability is usable from the desktop, and each flow was demonstrated in the manual run (recorded in STATUS.md).
- [ ] The honesty labels match `docs/mesh/USER_GUIDE.md` and SI-19.
- [ ] Reauth for enforcement is proven in core tests. No business logic was added to TS: reviewed, with STATUS noting any computed values and why they're display-only.
- [ ] Frontend, desktop and the full suite are green. CI's `desktop`/`frontend` jobs pass.

## Verification commands

The same commands as 09, plus:

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-cli --test mesh_cli
bash scripts/smoke.sh
```

## Docs to update

- `docs/mesh/USER_GUIDE.md`: desktop sharing, usage and caps, with the same honesty
  language.
- `docs/MANUAL_UI_TEST_PLAN.md`: a mesh projects/usage/caps section.
- `CHANGELOG.md`.

## Handoff checklist

- [ ] STATUS.md row 10 `done`.
- [ ] Handoff notes: the UI surfaces 11 will extend for credential sharing (which
      component should host "Share credential with my devices").
