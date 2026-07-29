# Migration: existing gateway users

Users who configured the Local Gateway by hand — routes, links, matching
authorization, a service install, environment edits — keep everything.
Nothing is deleted, duplicated, or re-created.

## What is adopted automatically

**Routes.** Setup looks up each selected provider's route row before
acting:

* a route that exists and is enabled → **reused** (no second row);
* a route that exists but is disabled → **re-enabled**;
* no route → **created**.

The plan shows which of the three applies per provider, and `track undo`
only removes routes this setup *created* — a route you made by hand, or
one another project still links, is kept and reported as kept.

**Links.** `envlink`'s existing slug-reuse means an existing
project↔route link keeps its link slug, so the base URL already written
into your `.env` stays valid. Re-running setup over an already-linked
project produces a no-change diff and writes nothing.

**The service.** An installed and running service is detected and left
alone. So is a foreground `gateway serve` — the plan reports "already
running" and skips installation entirely rather than fighting for the
port.

**Matching authorization.** Attribution is now part of turning on
tracking. If you already pushed a matching key, it stays; the
Start-tracking password field simply re-pushes it. Declining leaves
whatever state you had.

**Environment files.** The recorded pre-tracking state
(`prior_env_json`) is untouched by this milestone, so the undo semantics
you already had — restore the prior value, remove a variable Tethra
created, leave a value you changed yourself and report it — apply
unchanged.

## Schema

Migration **v15** adds one table, `tracking_setups`. It is additive
(SI-17): no existing table is altered, no data is rewritten, and older
rows are untouched. A database at v14 upgrades on first open; a database
written by a newer build is still refused rather than downgraded.

Backups pick the new table up automatically (backup v2 captures tables
generically).

**Executed upgrade evidence** (synthetic v14 database, 2026-07-27):

```text
before   user_version=14   tracking_setups absent   projects=1
after    user_version=15   tracking_setups present  projects=1
         idx_tracking_setups_project created
         PRAGMA integrity_check -> ok
```

The upgrade runs on first open by the new build, in a transaction, and
bumps the version only on full success — the existing `migrate_with`
contract. A database written by a newer build is still refused rather
than downgraded.

`project_repos` gains no column. New rows are stored canonicalized so
folder-first flows can match a selected directory to its project;
**existing rows are never rewritten** — comparisons canonicalize on read
instead. A path you registered as typed keeps its spelling.

## What is not migrated

* Setups made before v15 have no `tracking_setups` row, so the dashboard
  shows them as untracked until you run setup once over the folder. That
  run adopts the existing routes and links (no duplicates) and produces
  the tracking state. Your `.env` is not rewritten if it already points
  at the gateway.
* Nothing converts a manual link into a tracked setup automatically. This
  is deliberate: adopting a configuration silently would claim coverage
  Tethra has not verified.

## Advanced surfaces

The low-level screens and commands are unchanged and still fully
supported:

* Desktop: **Advanced → Gateway internals** — the previous Gateway view,
  including route and link forms, service actions, recording controls,
  and the matching-key toggles.
* Terminal: the whole `tethra gateway …` family.

Hand-made and automatic configuration remain interoperable because the
orchestrator writes only through those same APIs.

## If something looks wrong

`tethra track status` reports the state machine and per-provider
freshness; `tethra track doctor` gives the ranked diagnosis; `tethra
gateway doctor` gives the low-level service view. `tethra track undo`
restores only what tracking recorded, and reports anything it chose not
to touch.
