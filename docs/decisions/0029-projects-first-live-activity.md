# ADR 0029 — Projects are the surface; selecting a folder is the tracking action

Status: accepted
Date: 2026-07-29
Amends: ADR 0022 (zero-friction API tracking), ADR 0025 (current health vs
historical verification)
Preserves: ADR 0019, ADR 0020, ADR 0023, ADR 0024, ADR 0026, ADR 0027, ADR 0028

## Context

After PR #16 a user who wanted to see their API activity had to find a
top-level **Track API activity** item, work through a multi-screen flow, and
then look somewhere else again for the resulting data. Projects existed but were
a credential list: `ProjectDetail.tsx` rendered project metadata and a
credentials table and nothing about traffic.

The tracking machinery itself was in good shape — `crates/tracking` owns
detect → plan → apply → verify/health → diagnose → undo, and `tracking_setups`
already stored a `(project_id, folder_path)` row with a `config_generation` and
a `row_version` for compare-and-swap. What was missing was product-level: a
project had no *primary* folder, nothing compared the applied generation against
anything, unfinished credential findings had nowhere to live, and there was no
project-scoped read of observations.

Three constraints came out of reading the existing code and are the reason this
ADR exists rather than a straightforward UI move:

1. **`apply` had no consent artifact.** `tracking_apply` requires only that a
   plan exists (`apps/desktop/src-tauri/src/main.rs`). Folder-first, the wizard
   supplied the user's knowledge implicitly across several screens. Collapsing
   the wizard into one click would have removed that knowledge along with the
   screens — and what it conveys is that selecting a folder installs a login
   service, registers routes and rewrites `.env` files.
2. **The obvious read paths write.** `health::resolve*` compare-and-swaps up to
   `REFRESH_CAS_ATTEMPTS` times per setup, and `state::upsert_setup` is
   destructive by design (new verification session, generation + 1, `applied_at`
   and `first_traffic_at` cleared). A page that resolved health on a 5-second
   timer would perform a write storm; one that called `upsert_setup` on load
   would un-verify a healthy setup every time it opened. Separately,
   `tracking_status` and `tracking_list` use `with_vault`, which refreshes the
   inactivity clock — polling either would mean an open project page never
   auto-locks.
3. **Unknown-provider traffic has no gateway recording path.** A route cannot
   exist outside the compiled-in catalog (`routes.rs`), an unrouted prefix gets
   a 404 and one counter with no event row (`forward.rs`), and even routed
   traffic produces no row unless it arrived via `/p/<slug>/` (`writer.rs`). So
   "Unknown API at api.example.com — 12 requests" cannot come from the gateway
   for a genuinely unknown host. It comes from the interception path, whose
   `observation_source` is `intercept` and which records arbitrary hosts, or it
   comes from detection as "detected, not observed".

## Decision

**D1 — One primary folder per project, in its own table.** `project_folder_links`
(schema v20) has `project_id` as the PRIMARY KEY, so re-selecting a folder
updates one row instead of accumulating rows, which is what makes repeated
selection idempotent. It carries `tracking_enabled`, a `scan_fingerprint` and an
`applied_generation`. This is not a second tracking state machine:
`tracking_setups` still owns apply/health/verification per (project, folder), and
it could not express these facts because its key admits many folders per project
and its row is re-minted by `upsert_setup` on every apply.

**D2 — `applied_generation` gives the generation comparison a left-hand side.**
v16 added `config_generation` but nothing ever compared it to a desired value, so
"is the applied configuration still current?" had no answer. Storing the
generation an apply actually reached supplies one.

**D3 — A stat-only fingerprint, used to OFFER a rescan, never to perform one.**
`folder_fingerprint` hashes the (relative path, byte length, mtime) of
dependency and env manifests, bounded to depth 3 / 400 directories, refusing
symlinks, sorted before hashing so it is stable across runs. It reads no file
contents, so a relaunch can answer "did anything change?" without paying for the
20-second bounded scan. A stale fingerprint surfaces as `scan_stale`; the user
decides.

**D4 — A digest-gated confirmation is the consent artifact.** `prepare_link`
returns a `digest` over the decisions an apply would take and a `disclosure`
DERIVED FROM THE PLAN, so the screen cannot describe less than the plan does.
`confirm_link` re-plans and refuses a mismatch. This is the shape
`gateway_link_apply` already uses. It also closes a hole nothing else did: the
desktop's single tracking session survives a vault lock, so a plan previewed
before locking was still applyable afterwards; a digest re-checked against a
fresh plan cannot be.

The digest deliberately excludes `envlink::LinkPlan::digest`. That value covers
each file's previewed input and planned output, and the output embeds a per-link
CSPRNG slug — it differs on every `plan()` call, so binding it would reject every
confirmation including an immediate one. This digest binds the decisions
(service actions, route prefixes and providers, which files are touched and
whether each changes); the file bytes stay bound by `envlink::apply_link`, which
refuses independently at apply time. Two digests, two questions.

**D5 — Reads are split by cost.** `overview` resolves present-tense health and
belongs on page open, manual refresh and focus. `activity_only` reads
observations, touches no tracking state, probes no service and reads no files —
that is what the 5-second timer calls, through a `with_vault_background`
command so polling cannot defeat auto-lock.

**D6 — Unfinished credentials have no column for a value.** `detected_credentials`
cannot store a secret, so "a discovered plaintext is never persisted merely
because it was found in a project file" is a property of the table's shape rather
than of a predicate a later edit could loosen. Records are derived from
`Evidence::SecretEnvVarName`, whose own documentation states the value never
leaves the parse. A provider the project already holds a credential for produces
no unfinished record — asking for details Tethra already has would be a false
alarm — and is still reported in the preview so the detection is visible.

**D7 — Cost is re-derived at read time, with coverage.** `projectcost` reads
`gateway_usage_events`, not `gateway_usage_daily`: the rollup stores
`cost.unwrap_or(0)` into a NOT NULL column, so an unpriced request and a free one
are the same integer there. It keeps three cases apart — priced,
known-but-unpriced, and usage-never-reported — and reports coverage as a fraction
of KNOWN tokens, `None` rather than `0.0` when no tokens are known at all.
Re-deriving also means a pricing record added since the traffic arrived applies
to it, which is the documented point of effective dating.

**D8 — Naming an unknown API adds no table.** `observed_api_services` already
carries `user_provider` / `user_api_name` with `set_service_correction` to write
them, keyed by host — the right key, since a host is a host regardless of which
project reached it. A per-project label table would have been a second
implementation of a v12 feature, and the two would disagree the first time
either was written alone.

**D9 — The standalone flow is de-emphasised, not deleted.** Projects becomes the
primary navigation entry; **Track API activity** becomes **Tracking setup
(advanced)** under Advanced. Destination approvals, diagnostics and undo are
still only reachable there, and its behaviour is unchanged.

**D10 — The series reads raw events.** `aggregate::roll_up` returns early for an
incomplete hour, so `runtime_metric_buckets` never contains the hour a live view
is about. `projectactivity::project_series` aggregates
`runtime_request_events` directly, over the v16 `idx_rre_project_source_at`
index.

## Alternatives considered

**Auto-apply on folder selection with no confirmation.** Read literally, "the
user must not separately click Track API activity" could mean zero gates. It was
rejected: the same click installs a login service and edits the user's files, and
the prompt itself asks for "one concise disclosure before the first
configuration-changing action". One disclosure and one confirm is one gesture,
not a wizard.

**Reusing `tracking_setups` alone, with an `is_primary` column.** Rejected
because `upsert_setup` destroys and re-mints the row on every apply, so the
product-level facts (which folder is the project's, is tracking on) would be
lost each time the orchestrator ran.

**Polling `tracking_list` for the live page.** Rejected on two counts: it is
`with_vault`, so it defeats auto-lock, and it resolves health per setup, so a
5-second timer becomes a guarded-write storm.

**Adding a chart library.** Rejected: a large dependency in a
security-sensitive application for a deliberately temporary layout. The chart is
inline SVG with a text-equivalent table.

**Fabricating zeroes for continuity.** Rejected. A gap breaks the line, and only
requests/errors treat an absent bucket as a real zero, because only those are
counted from the observation rows themselves.

## Security implications

Nothing in the trust boundary moves. Specifically:

* Repository content remains evidence, never authorization. `Selections::defaults`
  is unchanged, so only `Configurability::Automatic` providers at `>= Likely` are
  configured, and a destination read from project files still needs its own
  per-destination approval (ADR 0024). A folder whose only integrations need
  approval yields a preview with no plan and an empty digest — a state, not an
  apply.
* No new value-bearing column, and no new value on any IPC boundary. The
  detected-credential table cannot hold a secret.
* Scanning still goes through the sealed, non-executing bounded reader (ADR 0023,
  ADR 0027). The fingerprint walk adds a stat-only pass that refuses symlinks and
  reads no contents.
* The gateway is untouched: same loopback bind, same registered upstreams, same
  custom-origin approval, same absence of payload/header/query persistence.
* Present-tense health still has exactly one resolver, and every tracking write
  is still a compare-and-swap.

## Future limitations

* Time to first byte is recorded per exchange by the gateway only; the intercept
  path does not separate it, so `ttfb_ms` is `null` on the project surface.
* Destination approvals are vault-wide (`tracking_approved_origins` is keyed by
  `(origin, provider_id)` with no project column), so the project page words them
  as pending rather than as this project's.
* `unlink` does not undo managed file changes. Restoring them stays the explicit
  `tracking_undo` action, so unlinking never edits a project file unasked.
* The layout is deliberately plain and expected to be replaced by a later visual
  redesign.
