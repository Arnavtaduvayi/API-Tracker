# Custom-origin approval under `--yes` (ORG-01) — independent evidence

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`.

## 1. Verdict

The refusal is **real, enforced and load-bearing**. A mutation that removes it
reproduces ZFT-004 verbatim — an enabled, MAC'd `gateway_routes` row pointing
at the attacker host — and **6 of 11 committed tests fail**. No path was found
by which `--yes` alone approves a custom origin, and no way for a repository
to impersonate a built-in provider.

## 2. Where the decision is made

The gate is in **shared core**, `crates/tracking/src/plan.rs`:

| Site | Role |
| --- | --- |
| `:53-63` `Selections::defaults` | auto-includes **only** `Configurability::Automatic` with confidence ≥ Likely |
| `:69-82` `pending_origin_approvals` | yields only `NeedsOriginConfirm` |
| `:87-91` `approve_origin` | the only way a repository-discovered destination enters a plan |
| `:406-411` | `NeedsOriginConfirm`/`NeedsOriginInput` without a `confirmed_origins` entry ⇒ **hard error**, not a silent skip |

Desktop and CLI cannot drift on the gate. The consent *loop* is duplicated
(`track_cmd.rs:389-498`; `main.rs:3506-3737`) — see `NEW-11`.

## 3. Every `--yes` branch traced (`track_cmd.rs:414-496`)

| Branch | Approves? | Persists? |
| --- | --- | --- |
| `describe()` policy refusal | no | no |
| `is_approved()` → Some (prior approval) | yes, silently | already persisted |
| `--allow-origin` given | yes | queued |
| `--dry-run` | no | no |
| **`--yes`** | **no** | **no** |
| stdin not a TTY | no | no |
| interactive `confirm_default_no` | on explicit "y" | queued |

Persistence happens only at `track_cmd.rs:669-677`, gated on
`report.failed_step().is_none()`. `origin::approve` has exactly two non-test
callers. `ctx::confirm_default_no` (`ctx.rs:284-296`) deliberately takes **no**
`assume_yes` parameter, unlike `confirm`. No environment variable acts as
`--yes`.

**Two honest carve-outs from the literal rule** (recorded as `NEW-12`, low):
`--yes --allow-origin X` *does* persist an approval (the flag is the explicit
decision), and `--yes` alone *does* proceed on run two after a first
interactive approval. Both are consistent with the documented
`PreviouslyApproved` model; the disclosure text never says the approval is
remembered permanently.

## 4. Scenario matrix

| Scenario | Behaviour |
| --- | --- |
| One unapproved custom origin | refused, exit 2 |
| Multiple | each refused independently (test asserts the refusal appears exactly twice) |
| Mixed built-in + custom | built-ins apply, custom skipped (`plan.rs:391` `continue`) — not a whole-run refusal |
| Only custom | `track_cmd.rs:499-502` "Nothing detected is automatically configurable yet" → exit 2 **before** apply |
| Previously approved exact origin | proceeds (`:436-445`) |
| Changed origin | requires reapproval — `is_approved` is an equality lookup on the canonical form |
| Non-interactive stdin | refused; a piped `y` is not consent (pinned) |

### Canonicalization (executed, via `--allow-origin`)

`origin.rs:233-236` → `routes::validate_origin` (`routes.rs:66-115`) →
`https://{host}:{port}`; host lowercased at `:106`.

| Spelling | Result |
| --- | --- |
| `https://host` | matches |
| `https://HOST` | matches (case-folded) |
| `https://host:443` / `:0443` | matches |
| `https://host/` | rejected — "must be a bare authority" |
| `HTTPS://host` | rejected — must be https |
| `https://host.` (FQDN dot) | parses, does **not** match |
| `https://user@host` | rejected — userinfo |
| `https://host:8443` | rejected — must use port 443 |
| `https://xn--80ak6aa92e.com` | parses, does not match |
| `https://аррӏе.com` (Cyrillic) | rejected |

Homographs cannot reach the consent screen: `is_valid_hostname`
(`crates/observe/src/policy.rs:425-439`) requires ASCII alnum/hyphen labels.

### Built-in impersonation — the key question

**A repository cannot impersonate a built-in provider.** Built-in vs custom is
decided by the **compiled-in manifest origin table**, and a project-set base
URL *demotes* the provider out of the automatic set
(`crates/tracking/src/detect.rs:1089-1165`):

* `providers::find(&provider_id) == None` ⇒ `Unsupported` — a repo cannot
  introduce a provider at all.
* fixed-origin provider with one non-manifest base URL ⇒ `NeedsOriginConfirm`
  (demoted, requires approval).
* custom-only provider (`origins = []`) ⇒ never `Automatic`.

The manifest match is anchored on the full origin followed by `/`
(`detect.rs:848-850`), so `https://api.openai.com.evil.example` and
`https://api.openai.com@evil.example` cannot satisfy it. Manifests are
`include_str!`-compiled (`providers.rs:252-304`) — there is no runtime
directory load. `routes::add_manifest_route` (`routes.rs:187-211`)
independently re-derives the origin from the compiled manifest.

## 5. Tamper-evidence and replay

`approval_mac` (`origin.rs:241-258`): keyed BLAKE3, domain-separated,
length-prefixed over `[vault_id, canonical_origin, provider_id, approved_at]`.

* **Tampered row ⇒ treated as absent**, not trusted (`:319-327`),
  constant-time compare. Pinned by `origin_trust.rs:318-357`.
* **Cross-vault replay fails on two independent bindings**: `vault_id` is a
  per-vault UUIDv4 (`vault.rs:176,190`) and the MAC key is fresh random per
  vault, wrapped with a vault-id AAD (`vault.rs:563-588`). *No test covers
  cross-vault replay* — the binding is sound but unpinned. Recorded as `NEW-13`.

## 6. Credentials cannot reach an unapproved host

1. unapproved ⇒ not in `selections.include` ⇒ `plan.rs:391` skips ⇒ no `RouteAction`
2. `apply.rs:463-518` iterates only `plan.route_actions` ⇒ no row
3. `add_custom_route` re-runs `validate_origin` and re-MACs
4. at forward time the route MAC is re-verified (`routes.rs:696-714`); a
   hand-inserted row is `Unforwardable`
5. `upstream::resolve_validated` re-checks every **resolved** address before
   dialing

Executed on the pristine build: the refused run leaves `gateway_routes = 0`,
`tracking_approved_origins = 0`, and the fixture `.env.development`
byte-identical.

## 7. Mutation test — the regression test is load-bearing

The refusal at `track_cmd.rs:470-481` was replaced with the pre-ADR-0024
behaviour (`--yes` approves and queues persistence). Run in an isolated copy
under `/private/tmp` with a separate `CARGO_TARGET_DIR`; `HostServiceOps::ensure_service`
stubbed so no `launchctl` write verb could execute (this machine hosts the
live production gateway).

**Pristine:** `11 passed; 0 failed`.
**Safety stub only:** `11 passed; 0 failed` — the stub is not load-bearing.
**Stub + security mutation:**

```
test result: FAILED. 5 passed; 6 failed

failures:
    a_near_miss_allow_origin_does_not_approve_the_repositorys_choice
    a_refused_run_creates_no_approval_record_for_a_later_run_to_inherit
    a_repository_cannot_disguise_a_custom_origin_as_a_builtin_provider
    a_yes_run_refuses_a_repository_chosen_origin
    a_yes_run_refuses_several_repository_chosen_origins
    no_credential_value_appears_on_the_refusal_path
```

Database proof under the mutation:

```
    → approved by --yes
=== gateway_routes ===
supabase|supabase|1|attacker-controlled.example.com|443|32
```

An enabled, MAC'd route to the attacker host, with the `.env` rewritten to
send the credential through it. The pristine binary, same fixture:
`exit=2`, `gateway_routes = 0`, `.env` untouched.

`control_allow_origin_approves_that_exact_destination` passes throughout — an
anti-vacuity control that stops "refuse everything" from satisfying the suite.

## 8. Secondary findings (none allow a credential to reach an unapproved host)

| ID | Sev | Finding |
| --- | --- | --- |
| `NEW-09` | Medium | The approval MAC binds vault, not project (`origin.rs:253`). Once `(provider, origin)` is approved in project A, **any other repository in the same vault** is auto-configured by `tethra track --yes` with no prompt (`track_cmd.rs:436-445`). The destination is already trusted, but the credential forwarded is the new project's. |
| `NEW-10` | Medium | `origin::list` (`:337`) and `origin::revoke` (`:374`) have **no production callers**. Approvals are permanent and cannot be viewed or withdrawn from the product — only by editing `vault.db`. |
| `NEW-11` | Low-Med | CLI/desktop drift on `PreviouslyApproved`: CLI auto-includes, desktop starts unchecked. |
| `NEW-12` | Low | `--yes --allow-origin` persists; disclosure never says approvals are remembered. |
| `NEW-14` | Low | `routes.rs:109-112` reports `BadHostname`/`BadPort` as "loopback, private, link-local, cloud-metadata" — misleading refusal text. |
| `NEW-15` | Low | `OriginTrust::may_configure_without_asking` (`origin.rs:65-71`) is dead code; its doc comment "the single place that decision is made" is false — both front ends hardcode `RepositoryDiscovered`. |
| `NEW-13` | Info | No cross-vault MAC replay test. |
| `NEW-16` | Info | `plan.rs:418-424` suppresses `ExistingOriginKept` when the pre-existing route is a manifest route — an approved redirect silently has no effect, with no warning. Fail-safe in direction. |
