# ADR 0013: Rotation, permission management, and temporary credentials

Status: accepted (2026-07-18)

Database migration v6 adds `rotations`, `rotation_events`,
`rotation_schedules`, `access_grants`, `credentials.provider_expires_at`,
and PID/grant columns on `process_sessions`.

## What rotation means here

Rotation is deliberately NOT "write a new value into a secret manager". The
durable workflow is: capability check → dry-run plan → reauthenticated
approval → replacement obtained → destinations updated and verified → the
new value validated against the provider → a configurable grace/overlap
period with continued-use detection → the previous key disabled where the
provider supports it → **revoked only after verification** → completed.
Every transition is a recorded event; the whole machine lives in SQLite, so
a crash or restart resumes exactly where it stopped (`rotation advance` is
the only engine — it re-reads persisted state and performs at most the next
step, idempotently; a stored replacement is never created twice).

### Provider reality (verified against manifests/official docs)

| Provider | Create | Disable | Revoke | Rotation mode |
| --- | --- | --- | --- | --- |
| OpenAI | Admin API (service-account keys in a provider project) | none exists | Admin API delete (permanent) | fully API-driven |
| Supabase | Management API (new-format secret keys) | none for new-format keys | Management API delete | fully API-driven |
| Anthropic | console only | Admin API `status=inactive` (reversible) | Admin API `status=archived` (**soft** — no hard delete; labeled as such) | guided manual create + API disable/archive |
| GitHub | web UI only | none | web UI (org admins have a narrow API path we don't hold credentials for) | guided manual, `complete-manual` confirmation |
| Stripe | dashboard roll | none | dashboard | guided manual |

Modes: `api_create` (provider create implemented AND an admin connection is
present) or `manual_create` (the workflow pauses at `awaiting_manual_key`
with dashboard instructions; `rotation provide-key` resumes it). When the
old key's provider-side id is unknown or the provider has no revocation
API, the workflow ends in `manual_required` and only a reauthenticated
`complete-manual` — which additionally requires that the new value was
validated — marks it completed.

### Safety decisions

- **Revocation is gated on verification**: `rotation_revoke_old` and
  `complete-manual` both refuse unless the new value passed a live
  validation. Destinations must have fully verified before validation even
  runs.
- **Continued-use detection**: during the grace period, provider usage rows
  attributed to the old key id since approval (OpenAI per-key data) block
  progression until `--acknowledge-continued-use`. Buckets are daily, so
  same-day rows may predate the switch — the message says exactly that and
  recommends a fresh `provider sync`. Where no data exists, nothing is
  claimed.
- **Rollback** restores the vault value (as a new auditable version, not by
  rewriting history), rolls destinations back via the rotation's sync plan,
  re-enables a disabled Anthropic key (`status=active` — the one reversible
  disable), and optionally revokes the key the rotation created. Once the
  OLD key was revoked, rollback is refused with an honest "irreversible;
  forward-fix" error — no provider here can resurrect a deleted key.
- **The old→new link handling**: the new provider key id is linked to the
  credential automatically (the approved rotation IS the user
  confirmation); the old link is kept so historical usage stays correctly
  attributed.

## Scheduled rotation is intent, never execution

A schedule can only be created after one manually approved rotation has
COMPLETED for that credential (the provider/destination combination is
proven). When due, the monitor runs a preflight (is the proven mode still
possible? is the credential alive?) and raises a high-severity
`rotation_due` alert — which the desktop app surfaces as a native
notification. Preflight failure pauses the schedule with the reason, and a
completed rotation re-arms it. **Nothing ever executes automatically**:
every destructive step still requires the user present, an explicit
confirmation, and the master password. This is a deliberate narrowing of
"automatic rotation" — our security model requires reauthentication before
changing secrets, and a scheduler cannot reauthenticate. The spec's
requirements (disabled by default, preflight, failure pause, no silently
queued destructive action, offline-safe) are all met by this design; the
part we refuse to build is unattended execution, and the docs say so.
`rotation_stuck` alerts flag in-flight rotations idle for 24h+.

## Permission changes route through replacement

No current provider supports editing a key's scopes via API (GitHub/Stripe
edit in dashboards; Anthropic/Supabase permissions are fixed at creation;
OpenAI scopes are dashboard-only). So the product offers: complete
visibility (GitHub exact header scopes; Supabase from the key format's own
self-description, including the legacy JWT `role` claim — read locally, no
network), a **before/after diff** (`key permissions-diff` fetches fresh
scopes without storing), permission snapshots in the audit trail, and a
change path that is honest: dashboard link where editing exists, otherwise
create-with-desired-scope + rotate. Nothing pretends scopes are mutable.

## Temporary access: local vs provider-enforced, never blurred

Three distinct things, each labeled everywhere it appears:

1. **Local access grants** (`access grant`, `run --grant`): bound what this
   machine injects — expiry window, one-time/max-launch counts (consumed by
   a single atomic UPDATE, so concurrent launches cannot double-spend),
   per-process kill timers (exit 124), PID-tracked termination, advisory
   budget warnings. Ending a grant stops new launches and can SIGTERM
   recorded processes; the CLI states plainly that injected values remain
   in a running process's environment and that local expiry **is not**
   provider revocation.
2. **Provider-reported expiration**: GitHub returns the token's expiration
   in an official response header during validation; it is recorded in a
   dedicated `provider_expires_at` column and drives the status engine with
   its own source label ("provider-reported"). None of the five current
   providers can CREATE short-lived credentials via API — that is stated,
   not simulated. A permanent key hidden behind a timer is exactly what
   this feature refuses to fake.
3. **Provider-created test keys** (`key test-create`): a real key created
   in a provider project (OpenAI service accounts; Supabase secret keys).
   Output separates PROVIDER-ENFORCED (project isolation, per-project usage
   attribution), NOT provider-enforced (the local TTL reminder — the key
   stays valid until revoked), and ADVISORY-ONLY (budget warnings). Expiry
   raises the normal expiration alert recommending `key provider-revoke`,
   which is confirmed + reauthenticated — never automatic.

## Lifecycle history and the rollback window

`key history` merges audit events, activity events, retained versions,
and rotation transitions into one chronological timeline (metadata only).
Retained versions now expire: the `rollback_window_days` setting (default
30, 0 disables age pruning; the 10-version count cap always applies) prunes
old versions at retention time and on unlock; SQLite `secure_delete`
overwrites the freed pages, which is the practical secure-deletion level a
local SQLite store can offer (documented in THREAT_MODEL.md).

## Alternatives considered

- **A background daemon executing scheduled rotations** — rejected: cannot
  reauthenticate, weakens the core security model, and turns a safety
  feature into an unattended destructive actor.
- **Auto-revoke at test-key expiry** — rejected: automatic destructive
  provider action violates the product's standing rule; an alert + a
  one-command confirmed revoke is nearly as convenient and fully honest.
- **Proportionally faking per-key usage for continued-use detection** on
  providers without per-key data — rejected (attribution honesty, ADR 0009).
- **Storing rotation state in memory with a journal** — rejected: SQLite
  rows + event log give restart recovery for free and match every other
  subsystem.

## Security implications

- The blast radius of rotation is bounded by ordering: nothing destructive
  happens before destination verification AND new-value validation, and
  revocation is last. Errors are recorded and retryable rather than pushing
  the machine into a destructive shortcut.
- `access end --kill` signals PIDs recorded at spawn time; PID reuse is
  possible in principle (documented), and an attacker who can forge rows is
  already inside the threat model's "malware as the user" exclusion.
- Provider admin credentials get more power in this milestone (create,
  disable, revoke). They remain vault-encrypted, write-only, and
  reauth-gated; the OpenAI/Anthropic/Supabase scopes required are listed in
  PROVIDER_SUPPORT.md.

## Future limitations

- Live verification against real provider accounts remains a manual
  opt-in script exercise (fixtures only in CI).
- GitHub org-admin fine-grained-token revocation (the one narrow API path)
  is not implemented — we hold user tokens, not org-admin tokens.
- OpenAI project rate limits (`/v1/organization/projects/{id}/rate_limits`)
  could add provider-enforced request caps for test keys later.
