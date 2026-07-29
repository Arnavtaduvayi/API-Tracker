# ADR 0021: Custom-origin route verification key — lifecycle and installation

Status: accepted (2026-07-26). Amends ADR 0019 D3. Supersedes nothing.

**Superseded in part (2026-07-29, SEC-01 / NEW-49).** The framing sentence below overstates the MAC's reach. It protects the *destination of a custom origin*: no destination the user never approved can be injected or substituted, and an edited stored origin stops the route rather than redirecting it. It does **not** cover built-in routes, whose destination is selected by an unauthenticated `provider_id` column, and it does not survive a row downgrade — nulling `custom_origin`, `custom_origin_port`, `custom_origin_mac` and `custom_origin_consent_at` together moves the row onto the built-in path, where the MAC is never consulted. Both require local write access to `vault.db` and are an accepted, out-of-scope risk. See `docs/gateway/SECURITY.md` ("What database tampering can and cannot do to your routes"), `docs/gateway/THREAT_MODEL.md` GW-3, and `docs/activity-onboarding/SECURITY_AND_PRIVACY.md` ("the local-database attacker"). The key-lifecycle decision recorded below is unaffected.

ADR 0019 D3 designed custom-origin routes (Supabase-style per-project hosts) to carry a MAC under a vault-derived key, so the plaintext, same-uid-writable `gateway_routes` table is never the trust root for where a live pass-through credential is forwarded (scoped as above). The gateway verifies the MAC before forwarding; a route whose MAC cannot be verified is not forwarded.

The final independent audit of `feat/local-gateway` found that `RouteState::set_mac_key` — the only way the verification key can reach a running gateway — **had no callers anywhere in the tree**. Every custom-origin route was therefore permanently unforwardable, answering a 503 whose text told the user to unlock their vault, which installed nothing. The feature could not be used at all.

This ADR defines the key's lifecycle and records the answers the remediation had to settle before wiring a caller.

## What this key is, precisely

| Question | Answer |
| --- | --- |
| Root material | A random 32-byte key created on first use and stored vault-key-wrapped in `vault_meta.wrapped_gateway_mac_key`, with AAD `gateway_mac_key(vault_id)`. It is **not** derived from the fingerprint key or from the master password. |
| Domain separation from the matching key | Total. Different key material, different storage, and the MAC's own domain string (`tethra:gateway-route-mac:v2`) separates it from any other keyed hash in the system. |
| Can it reveal or validate a credential? | **No.** It is used only for a BLAKE3 keyed hash over route identity fields (vault id, route prefix, provider id, origin host, port, consent timestamp). It cannot decrypt anything and cannot produce or confirm a credential fingerprint. |
| Can it modify routes, verify routes, or both? | **Both**, because the MAC is symmetric — anyone holding the key can mint a valid MAC. This is stated plainly rather than glossed: see "Why symmetric" below. |
| Does route management require an unlocked vault? | Yes. Adding, removing, enabling, and disabling routes all go through `with_vault` / `ctx.unlocked()`. The gateway itself never writes a route row. |

## When it is installed

Installed into the running gateway over the authenticated control channel (`Request::PushRouteKey`, SI-21) — never over the TCP listener, never via argv or an environment variable, and never read back.

Pushed by every flow that has an unlocked vault and could plausibly precede a custom-route request:

- **Adding a custom route** (CLI `gateway route add --origin`, desktop route panel). This is also the only place the key is *minted*: creating a custom route is the moment the key legitimately comes into being.
- **Vault unlock** (CLI `vault unlock`, desktop `vault_unlock`) — this is what makes the 503's "unlock Tethra once" instruction true.
- **Re-enabling a route.**
- **Foreground `gateway serve`** when the shell has a vault session; when it does not and unverifiable custom routes exist, `serve` says so instead of leaving the user to discover a silent 503.

Never minted as a side effect: a vault that has never had a custom route does not acquire route-signing material because the user happened to run `vault unlock`. `routes::route_key_exists` gates that.

**Not reauth-gated.** Unlike the matching key, this key is not a credential oracle — it cannot decrypt or confirm anything about a credential. Gating it behind a password prompt would buy nothing and would leave the user's own consented routes broken until they typed one. The *creation* of a custom route is already an explicit, confirmed, audited action.

## When it is cleared

| Event | Effect |
| --- | --- |
| `RevokeRouteKey` (explicit) | Cleared; custom routes return to 503, manifest routes unaffected |
| Gateway process stop | Gone with the process |
| Service restart | **Not** reconstructed — nothing persists it. Custom routes are unavailable until a vault session installs it again. This is the documented "locked since boot" outage window. |
| **Vault lock** | **Retained.** See below. |

### Why lock does not clear it

This is the deliberate, disclosed difference from the matching key (ADR 0020), and it goes the other way for a reason.

Dropping the route key on lock would stop forwarding for every custom route the moment the user's vault auto-locked — breaking ADR 0019 D4's immutable property that **the gateway forwards while the vault is locked**. The user's linked Supabase project would start failing mid-afternoon because a timer elapsed. That is a real, immediate harm.

The security it would buy is close to zero: the key confirms that a route row was authored by this vault. It is not an oracle over credentials, and an attacker who can read the gateway's memory to steal it is a same-uid attacker who is out of scope repo-wide and could read the vault directly.

So: the matching key is dropped on lock because it is a credential oracle whose residency the user's own auto-lock decision should bound. The route key is retained because it is not, and dropping it would break forwarding. Both rules are stated in the code, in SECURITY_INVARIANTS, and in THREAT_MODEL.

## Why symmetric, and what that costs

An asymmetric scheme (sign at consent time with a vault-held private key, ship only the public key to the gateway) would be strictly stronger: a gateway-memory compromise could then verify but not mint. It was considered and not adopted for v1:

- It requires a new signature dependency in security-sensitive code, against a repo goal of minimal audited dependencies (the branch currently adds **zero** net-new third-party crates).
- The threat it closes requires an attacker who can *both* read gateway process memory *and* write the vault database. Anyone who can do both is a same-uid attacker, already out of scope, and already able to read the unlocked vault.
- The threat the current scheme *does* close — the one ADR 0019 D3 was written for — is a bare `UPDATE gateway_routes SET custom_origin = ...` by something that can write the plaintext DB but cannot read gateway memory. Symmetric MAC closes that completely.

Recorded as a known limitation rather than hidden: **a process that can read the running gateway's memory can mint a route MAC.** If the threat model ever admits that adversary, this becomes asymmetric.

## MAC v2: binding the route prefix

The v1 MAC covered (vault id, provider id, origin host, port, consent timestamp) but **not the route prefix**. A MAC'd row could therefore be transplanted onto a different prefix — the MAC would still verify, and a request carrying one provider's pass-through credential to `/openai/...` could be forwarded to a different provider's registered origin.

v2 binds `route_prefix`. The domain string is versioned (`...:v2`), so a v1 MAC does not verify under v2 and the route reports `MacMismatch` — fail closed — rather than being silently accepted.

**Migration:** none is needed. Custom routes have never been forwardable in any build, so no working custom route exists in the field to break. A row created by an earlier build shows as `MacMismatch` with the existing "re-register the route in Tethra" guidance, which is the correct action.

## Load-time origin re-validation

The load-time re-check now validates the **stored** port. Previously it synthesized `https://{host}` and therefore always re-checked port 443 regardless of what the row said, which is not the "full origin policy" the code claimed to re-run. The MAC covers the port, so this is defense in depth — which is exactly the role the comment claims for it.

## Status honesty

`Status.route_key_present` distinguishes the two kinds of unavailable: *no verification key installed* (fixable by unlocking) from *tampered or corrupt row* (fixable only by re-registering). The CLI `route list` and the desktop routes panel previously loaded the table with **no key unconditionally**, so a just-added custom route always displayed "unavailable" even while a running gateway forwarded it correctly. Both now verify with the real key when a session exists, and when it does not they say "cannot be verified from this view while the vault is locked — a running gateway may still be forwarding it" instead of asserting unavailability they cannot know.

## Tests

`crates/gateway/tests/custom_routes.rs`, 13 tests:

- `a_custom_route_becomes_forwardable_once_the_key_is_installed` — the blocker, end to end: unforwardable without the key, resolves to the registered origin with it, and a real request through the listener reaches the upstream with the prefix stripped.
- `a_custom_route_without_a_key_answers_503_not_a_forward` — the honest unavailable state.
- `the_control_channel_installs_the_route_key_into_a_running_service` — the wiring: a real `Service`, a real control call, status confirming residency.
- `a_tampered_origin_still_fails_closed_with_the_key_installed` — verification is not weakened into acceptance.
- `a_maced_row_cannot_be_transplanted_onto_another_prefix` — the v2 binding.
- `a_stored_non_443_port_is_rejected_at_load_even_with_a_valid_mac` — the load-time port re-check.
- `removing_or_disabling_a_custom_route_stops_forwarding`.
- `an_unregistered_origin_is_never_reachable_through_a_custom_route` — unknown prefix, prefix confusion, absolute form, traversal; zero upstream connections.
- `a_vault_lock_keeps_the_route_key_but_drops_the_matching_key` — the two lifecycles cannot be conflated.
- `a_restarted_service_has_no_route_key_until_a_session_installs_one`.
- `pushing_a_route_key_requires_the_control_nonce`, `a_malformed_route_key_is_refused`, `the_route_key_and_the_matching_key_are_independent`.

## Security implications

The gateway still cannot act as an open relay: origins come only from the compiled-in manifest or a MAC-verified row, never from anything in the request. Installing the verification key does not widen what the gateway will forward to — it only lets the gateway *check* rows the user already consented to. A tampered row fails closed rather than falling back to an unverified accept.
