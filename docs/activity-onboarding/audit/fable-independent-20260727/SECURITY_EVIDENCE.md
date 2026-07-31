# Security Evidence — Independent Audit of PR #16

Two separate questions are answered here:

1. **Did the existing gateway security posture regress?** — No. The forwarding
   plane is intact and fully tested.
2. **Is the new automation trustworthy?** — No. Three ship-blocking defects:
   arbitrary code execution during scanning, attacker-influenced route origins,
   and verification that can be made to claim success falsely.

---

## 1. Gateway black-box suite — re-run, not quoted

```
$ cargo test -p api-tracker-gateway
269 passed, 0 failed, 8 ignored (perf only), exit 0
```

Per binary: lib 75, `adversarial_blackbox` 17, `control` 24, `custom_routes` 13,
`doctor` 5, `envlink` 22, `forwarding` 44, `helper_discovery` 6, `lifecycle` 15,
`no_insecure_verifier` 6, `privacy_canaries` 9, `routes` 11, `schema` 5,
`writer` 17.

| # | Threat | Test | Result |
|---|---|---|---|
| 1 | Open relay | `audit_absolute_form_and_connect_never_reach_an_upstream` | PASS |
| 2 | Absolute-form targets | same (3 variants incl. one naming a *registered* origin) | PASS |
| 3 | CONNECT | same + `connect_absolute_form_upgrade_and_http10_are_refused` | PASS |
| 4 | Authority-form | `adversarial_blackbox.rs:100` | PASS |
| 5 | Protocol-relative (`//evil.com/…`) | `:102`, `:201` empty-first-segment | PASS |
| 6 | Foreign Host header | `audit_host_header_override_is_refused…`, `the_host_gate_accepts_only_this_gateways_own_loopback_authority` | PASS |
| 7 | Prefix confusion | `audit_prefix_and_encoding_confusion_cannot_reach_or_escape_a_route` | PASS |
| 8 | Encoded traversal | `audit_encoded_slash_traversal_is_rejected_and_cannot_cross_origins` | PASS |
| 9 | Smuggling (CL.TE / TE.CL / dup CL) | `audit_every_smuggling_shape_is_rejected…`, `audit_a_smuggled_second_request_never_appears_upstream` | PASS |
| 10 | CRLF injection | `audit_crlf_in_path_or_header_cannot_inject_a_header_upstream` | PASS |
| 11 | Redirect escape | `audit_a_redirect_to_an_unregistered_origin_is_relayed_never_followed` | PASS |
| 12 | Oversized heads | `audit_oversized_head_and_header_flood_are_bounded` | PASS |
| 13 | Header floods | same | PASS |
| 14 | Slowloris | `audit_slowloris_is_dropped_within_the_documented_deadline` | PASS |
| 15 | Connection limits | `audit_connection_cap_answers_503_and_never_grows_unbounded` | PASS |
| 16 | Truncated upstreams | `audit_a_truncated_upstream_body_is_terminal…`, `…502_not_a_silent_drop` | PASS |
| 17 | Cookie stripping | `audit_cookies_are_stripped_in_both_directions` | PASS |
| 18 | Browser drive-by | `audit_browser_shaped_requests_are_refused_and_leave_no_observation_row` | PASS |
| 19 | Cross-route credential isolation | `cross_route_requests_never_share_an_upstream_socket` | PASS |
| **20** | **Auto-route origin provenance** | **no test** | **gap — `ZFT-004`** |

Every named threat is covered and passing. The only coverage gap is the new
attack surface this PR introduces.

### The gateway diff carries no relaxation

* `routes.rs` (+2 / −2): a doc-comment typo fix. `validate_origin`, `route_mac`
  v2, `add_custom_route` and load-time re-validation are byte-identical.
* `envlink.rs` (+73): planning-only additions; `plan_link` delegates with an
  empty projection, reducing to prior behaviour; digest and write paths unchanged.
* `forwarding.rs` test edit **strengthens** the 304 assertion.

**Auto-created routes are not weaker than manual ones.** They call the identical
`routes::add_manifest_route` / `add_custom_route` (`apply.rs:417,432`) that
`tethra gateway route add` calls — same MAC, same consent timestamp, same
`enabled=1`, same validation. Controls confirmed live: a loopback origin and a
plaintext-`http` origin are both **rejected** on the auto path. Cross-route
credential binding is 1:1 (route prefix is always the provider id) and
`route_mac` v2 additionally binds the prefix, so a transplanted row fails closed.

---

## 2. ZFT-001 — Arbitrary code execution during folder scan (CRITICAL)

Reproduced first-hand against the packaged helper. Full detail in
`FINDINGS_INDEX.md`. Summary:

```sh
git init -q . && git config core.fsmonitor "$PWD/payload.sh"
printf 'OPENAI_API_KEY=sk-proj-RCEPROBE\n' > .env
tethra track "$PWD" --dry-run
→ PAYLOAD EXECUTED ×4
```

Chain: `detect.rs:347` → `envgov::discover` → `git_status_of`
(`envgov.rs:118-139`) → `Command::new(git_program())` (`gitrepo.rs:123`).
`git ls-files --error-unmatch` and `git check-ignore` honour the scanned repo's
own `core.fsmonitor`, which git spawns. `safe.directory` does not protect: it
fires only for repos owned by a *different* user, and a clone is owned by the
user who cloned it.

**Why this is the worst finding in the audit:**

* It fires in `--dry-run`, the mode that promises *"nothing was changed"*, on a
  screen that prints *"nothing executed or uploaded"*.
* In the desktop app `tracking_scan` runs the instant a folder is picked
  (`main.rs:3146`) — so the trigger is *clicking a folder*, before any
  confirmation.
* The product's primary call to action invites users to point it at project
  folders, which developers routinely clone from the internet.
* Three tests appear to cover this and none do:
  `bounds.rs:238 detection_source_makes_no_network_calls` is a textual
  `include_str!` grep; `bounds.rs:172 env_files_are_parsed_never_executed` scopes
  to the env parser only.

---

## 3. ZFT-004 — Route origins are taken from repository content (HIGH)

A fixture containing **no secrets** — a committed `package.json` naming
`@supabase/supabase-js` and a committed `.env.development` with
`SUPABASE_URL=https://attacker-controlled.example.com` — produces:

```
supabase    likely
Will do:
  2. create routes: supabase → https://attacker-controlled.example.com
```

Carried through a real `--yes` apply, the route was MAC'd, enabled, persisted in
`gateway_routes`, the verification key pushed into the live service, and the
app's `.env` rewritten to route its credential through the local gateway to the
attacker's host.

`SECURITY_AND_PRIVACY.md:76-81` promises this *"requires an **explicit
checkbox** (never part of Confirmed auto-config)"*. There is no checkbox in the
CLI; the desktop ships it **pre-checked** with the origin **pre-filled**.

The transport defenses did their job — loopback, private, link-local, CGNAT,
cloud-metadata, non-443 and plaintext origins are all still refused, and
template-class files (`.env.example`/`.sample`/`.template`/`.dist`) are never
value-read, so the first attack attempt through `.env.example` correctly failed.
What regressed is the **provenance** of the one input those defenses cannot
judge: the destination host itself.

Mitigation that does hold: two or more conflicting inferred origins downgrade to
`NeedsOriginInput`, which is *not* auto-confirmed — a user with their own real
`.env` present is protected.

---

## 4. Verification integrity — attack matrix

Executed black-box against the packaged helper with a live foreground gateway,
plus a purpose-built harness for the DB-level cases.

| Axis | Attack | Result |
|---|---|---|
| A | No restart, no traffic | **Refuses correctly** — `State: waiting — restart the project, then make one request` |
| B | Timeout fall-through | **Refuses correctly** — CLI prints ranked diagnoses and exits 2; desktop stays `waiting`. No success branch exists. |
| C | Unrelated local traffic (`/_tethra/health`, closed port) | **Refuses correctly** — `/_tethra/*` dropped pre-routing; other ports never reach the table |
| D | Wrong route (bad slug, wrong prefix) | **Refuses correctly** — 404, no observation row |
| D′ | Second folder in the *same project* | **FAILS** — folder B is "verified" by folder A's traffic. `refresh` filters `project_id` only; the provider is resolved from the observed **host**, not the route prefix or link slug. |
| E | Reuse of an old observation | **FAILS** — see `ZFT-006`, `ZFT-008` below |
| F | Gateway stopped before verification | **FAILS** — `ZFT-005`, reproduced first-hand |
| G | Route deleted / corrupted | **FAILS** — `DELETE FROM gateway_routes` leaves the row reporting verified |
| H | Base URL overridden after setup | **FAILS** — drift is detected only on the no-traffic branch, which a verified setup never reaches |
| I | SDK ignores the env var | Honest while nothing arrives; but overclaims once *any* local process touches the link URL |
| J | Correlation / session spoofing | **No token exists.** Nothing to replay because nothing is checked — see below |
| K | State overclaim / "re-derives on read" | **CLAIM FALSE** — `ZFT-008` |
| L | "configured" vs "observed" conflation | Enum is honest; but the CLI renders `PartiallyObserved` as `✓ Tracking verified for X` — one provider observed out of N completes the flow |

### What "a qualifying new observation" actually is

`state.rs:357-361`, in full:

```sql
SELECT host, MIN(at), MAX(at) FROM runtime_request_events
 WHERE project_id = ?1 AND observation_source = 'gateway' AND at >= ?2
 GROUP BY host
```

with `?2 = setup.applied_at`. That is the entire mechanism.

* **Not** a monotonic id or rowid watermark — a **wall-clock RFC 3339 string**
  compared **lexicographically**. Non-monotonic; NTP- and clock-step sensitive.
* **No** session id, nonce, correlation token or run id anywhere in the
  verification path. Nothing binds an observation to *this* setup or *this* run.
* Baseline captured **after** apply's side effects (`record_applied` is step 10;
  the keyless probe is step 8).
* Comparison is `>=`, not `>`.
* Filters present: project, source, time. Filters **absent**: route prefix, link
  slug, port, setup id, folder.

**Ordering bug (`ZFT-006` sibling):** `time`'s RFC 3339 omits the fractional part
when nanoseconds are zero, and `'Z'` (0x5A) > `'.'` (0x2E). Demonstrated:

```
earlier="2026-07-27T12:00:00Z"  later="2026-07-27T12:00:00.4Z"   (earlier >= later) == true
```

An observation recorded 400 ms *before* `applied_at` satisfies the test.

**Tethra's own probe is recorded as ordinary project traffic.** The step-8
keyless probe requests `{base_url}/models` with no probe marker
(`verify.rs:64-77`); `base_url` embeds the project link slug, so `resolve`
attaches `project_id` and the writer persists a full event. It does not verify
by itself only because `applied_at` is stamped two steps later — but under
`ZFT-006` or a clock step, it does.

**Consequence for the honest reading of "verified":** it means *"some local
process used this project's link URL at some point after the watermark"*. A
single `curl http://127.0.0.1:PORT/p/<slug>/openai/v1/models` satisfies it. The
slug is written in cleartext into the project's `.env`, readable by every process
running as the user.

### Mutation check on the load-bearing assertion

Target: `AND at >= ?2` (`state.rs:359`) — the sole definition of "new".
Baseline 25 passed / 0 failed in the throwaway copy.

| Mutation | Caught? |
|---|---|
| watermark neutralized (`OR 1=1`) | **CAUGHT** — `pre_existing_traffic_never_verifies_a_new_setup` |
| `>=` → `>` (boundary flip) | **SURVIVES** |
| `observation_source='gateway'` neutralized | **SURVIVES** |
| `project_id` neutralized | **CAUGHT** — `another_projects_traffic_never_verifies_this_setup` |
| downgrade arm → `None` | **CAUGHT** — `an_overclaiming_row_is_downgraded_on_refresh` |

Three guard tests, two load-bearing clauses with **zero** coverage. The surviving
`observation_source` mutant matters: that filter is the only thing preventing
`observe`/`run` proxy sessions — which write to the same table for the same
project and hosts — from satisfying gateway verification.

---

## 5. Authorization and lifecycle

**Genuinely automatic — confirmed.** Enabling tracking configures the matching
capability inline (apply step 9) with no separate consent screen and no hidden
step. The retained password field is the ADR 0020 reauthentication, enforced in
core (not the UI), optional, and degrade-not-block. Forwarding demonstrably
continues when attribution pauses (`forwarding_continues_after_the_lock_revokes_the_key`
passes). No shell export is required anywhere in the tracking flow.

**Obeys the established lock and TTL policy — confirmed.** `tracking_apply` and
`tracking_resume_attribution` use the identical `Request::PushKey` control path
into the same `ServiceControl::push_key`; lock coupling and TTL are service-side.
`MATCH_WHILE_LOCKED_TTL_CAP_MINUTES = 480` with a real poller thread; dual-clock
expiry; fail-to-revoke on unreadable config; never persisted; a restarted service
never reconstructs the key (test-pinned). Keys exist at rest only vault-wrapped.
Zeroized on revoke; hex copies wrapped in `Zeroizing`; manual `Debug` redacts.

**Not honestly disclosed — `ZFT-013`, HIGH.** The Advanced dialog discloses the
memory-oracle residual properly. The new primary flow authorizes the *same*
capability with only *"Label traffic with which stored credential was used"*.
`SECURITY_AND_PRIVACY.md` §2 claims the residual was "carried over verbatim" —
false in the shipped UI. (The GW-11 standing-relay disclosure *was* carried over,
so this is a specific omission, not a general one.)

**IPC surface.** All ten `tracking_*` commands require an unlocked vault except
the two foreground ones; none returns secret material; two accept the password.
A compromised webview could reconfigure tracking — but it had exactly that
authority pre-PR via `gateway_route_add` / `gateway_link_apply`. **No expansion
of the IPC trust model.** The only new capability is `dialog:allow-open` (not
`dialog:default`, no `fs:*`) — appropriately narrow. The vault change (56 lines,
path canonicalization + a reverse lookup) is **benign**: no change to KDF
parameters, lock behaviour, zeroization, the reauthentication requirement, or
decrypted-value lifetime.

**Failure visibility.** Every apply step failure is a named `Failed` step that
stops the sequence and persists `needs_attention`. Soft spots: every lifecycle
error is labelled "macOS blocked the background service (unsigned build)"
(`ZFT-039`); `attribution_is_paused` fails toward "healthy" on control errors
(`ZFT-031` sibling); one swallowed `let _ = store::save_config` (`apply.rs:379`);
a wrong master password reports as "skipped", not failed.
