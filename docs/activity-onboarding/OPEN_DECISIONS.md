# Open Decisions — Zero-Friction API Tracking

Numbered O-22-n (ADR 0022 series). Each has a default so work is never
blocked; "owner-moment" marks when it must be closed.

## O-22-1. Stripe/GitHub gateway support via manifest expansion

Stripe and GitHub are detected but `Unsupported { NoConfigurableBaseUrl }`
(no `[gateway]` manifest section). stripe-python honors `STRIPE_API_BASE`
in some versions; stripe-node and octokit take base URLs in code, not env.
**Default:** ship without them; the review screen says so honestly.
**Owner-moment:** provider-manifest expansion after verifying each SDK's
actual env-var behavior against official docs (never assume).

## O-22-2. Auto-repair on version drift

When the bundled helper is newer than the installed service binary, does
`track` run `Lifecycle::repair` inside apply without an extra prompt?
**Default:** yes, as a named step in the apply report (repair is
install(force) of the same product the user already consented to; the
report keeps it visible). **Owner-moment:** Phase 3 review.

## O-22-3. Attribution in non-interactive CLI runs

`track --yes` cannot prompt for the master password. **Default:** include
attribution only when `TETHRA_PASSWORD` is set; otherwise skip with a
printed note (never fail the run, never cache a password).
**Owner-moment:** Phase 2.

## O-22-4. Waiting-window durations

10 s before showing the restart instruction, 120 s before auto-diagnosis
(UI); CLI waits until Ctrl-C with the same hints. **Default:** as stated;
tune with real usage. **Owner-moment:** Phase 4 polish.

## O-22-5. Multi-folder and monorepo projects

A project with several registered repo paths, or a monorepo where the
selected folder is a sub-package: which env files and manifests count?
**Default:** scan exactly the selected folder (sub-package selection is
therefore already supported); a project may hold several tracking setups
(one per folder), `UNIQUE(project_id, folder_path)`.
**Owner-moment:** Phase 1 API freeze.

## O-22-6. Detection signal expansion

Source-import scanning, `Cargo.toml`/`go.mod`/`Gemfile`, nested
`package.json`. **Default:** out of scope this milestone; fusion API is
built to absorb new `Evidence` variants. **Owner-moment:** post-ship
backlog.

## O-22-7. Dashboard data unification

The dashboard renders gateway-observed, proxy-observed, and
provider-reported series side by side, never summed (KNOWN_CONFLICTS C8).
Is a per-provider "best available" headline number acceptable if labeled?
**Default:** no headline merging in v1; three labeled sections.
**Owner-moment:** Phase 4 design review.

## O-22-8. Coordination with PR #14 (sidebar shell redesign)

PR #14 (`eesh-ui`) rebuilds the desktop shell this plan regroups.
**Default:** phases 1–3 are UI-free and unaffected; before Phase 4, rebase
on whichever shell is on `main`, else land grouping in the current top bar
and let #14 restyle. Do not merge or modify #14 from this branch.
**Owner-moment:** start of Phase 4.

## O-22-9. Process finding: PR #15 merged against its own audit gate

`docs/gateway/HANDOFF_PHASE_5.md`, `docs/gateway/audit/RE_AUDIT_HANDOFF.md`
and `docs/gateway/audit/REMEDIATION.md` all required a fresh independent
re-audit before merge; GitHub shows PR #15 merged 2026-07-27 with no
re-audit recorded in the tree. This phase adds dated status-correction
notes (Phase 0) so the docs stop asserting a false repo state, but the
underlying decision — whether to commission the re-audit post-merge —
belongs to the repository owner. **Default:** flag, correct the records,
proceed on merged `main` (the merge is a fact this plan cannot unwind).
**Owner-moment:** owner's call, independent of this feature.

## O-22-10. `observed_api_services` seeding from detection

Seed "detected in repo, not yet observed" services via the existing unused
`ServiceSource::RepositoryDetected`? Gives the dashboard an honest
coverage view; costs inventory noise. **Default:** defer to Phase 4+
behind the dashboard design. **Owner-moment:** Phase 4.
