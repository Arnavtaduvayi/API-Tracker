# ADR 0024: Repository content is detection evidence, never authorization

Status: accepted (2026-07-27) — remediation of ADR 0022 following the
independent audit of PR #16 (`ZFT-004`, `ZFT-012`, `ZFT-025`, `ZFT-027`).

Amends ADR 0022 D5/D7. Changes no mechanism in ADR 0019 (route validation,
MAC, SSRF policy) — those were correct and are unchanged.

## Context

`SECURITY_AND_PRIVACY.md` promised that a custom route origin "requires an
**explicit checkbox** (never part of Confirmed auto-config)".

The audit built a fixture containing **no secrets at all** — a committed
`package.json` naming `@supabase/supabase-js` and a committed
`SUPABASE_URL=https://attacker-controlled.example.com` — and Tethra created
a MAC-authenticated, enabled route from the user's local gateway to that
host, pushed the verification key into the running service, and rewrote the
app's `.env` so its credential flowed through it.

There was no checkbox in the CLI. The desktop shipped it **pre-checked**
with the origin **pre-filled**. The root cause was four lines:
`Selections::defaults` matched `Configurability::NeedsOriginConfirm` and
inserted the provider into `include` **and** the inferred origin into
`confirmed_origins` — the confirmation the variant is named for was
satisfied by the code that was supposed to ask for it. The only remaining
gate was one bulk `confirm("Proceed?", yes)`, which `--yes` answers.

The gateway's transport defences did their job throughout: `validate_origin`
correctly refused loopback, plaintext HTTP, private networks, userinfo,
paths and non-443 ports. What regressed is **provenance** — the one input
those defences cannot judge. A host can be perfectly well-formed, public,
HTTPS, and still be the attacker's.

A second, quieter version of the same confusion: for a **fixed-origin**
provider, the mere *presence* of `OPENAI_BASE_URL` counted as an
independent signal that promoted the detection to `Confirmed`, and the
route was then built to the manifest origin. A user behind LiteLLM, a
corporate LLM gateway or a self-hosted proxy had their traffic silently
re-pointed at OpenAI, carrying their key, with the removed line masked in
the diff so they could not see what was being replaced (`ZFT-012`).

## Decision

### D1. Three trust classes, one decision point

```rust
enum OriginTrust {
    BuiltInManifest,                       // shipped by Tethra
    PreviouslyApproved { approved_at },    // this exact origin, by this user
    RepositoryDiscovered,                  // read from project content
}
```

`may_configure_without_asking()` is the single place the decision is made.
`BuiltInManifest` and `PreviouslyApproved` return true;
`RepositoryDiscovered` returns false, always.

**Built-in origins stay automatic.** This is what keeps the zero-friction
promise: a compiled-in manifest value cannot be influenced by the
repository, so `api.openai.com` needs no prompt, and a project with ten
supported providers is still four clicks.

### D2. `Selections::defaults` includes only `Automatic`

`NeedsOriginConfirm` is no longer selected by default and its origin is no
longer pre-filled. `Selections::pending_origin_approvals` returns what
needs a decision, and `Selections::approve_origin` is the **only** way a
repository-discovered destination enters a plan.

### D3. Approving a destination is a separate answer from approving the setup

* **Interactive CLI:** one prompt per destination, default **no**, showing
  scheme, host, port, provider, the source file and variable, whether
  credentials will be forwarded, and the network class.
* **Non-interactive CLI:** `--allow-origin <url>`, repeatable, matched on
  the canonical origin. `--yes` **refuses** repository-discovered
  destinations by design and says why — it answers "run the setup", not
  "send my API traffic to a host this repository chose".
* **Desktop:** one checkbox per destination, default **off**, labelled with
  the destination host and carrying the same disclosure. Clicking "Start
  tracking" does not approve them. Several destinations arrive as one
  review screen with individually unchecked boxes, so thirty detected APIs
  do not become thirty dialogs.

The disclosure text is built by one Rust function used by both frontends,
so the two consent surfaces cannot drift.

### D4. Approvals are per exact origin, and tamper-evident

`tracking_approved_origins` (migration v17) stores the canonical
`https://<host>:<port>`, the provider id, the timestamp, and a keyed
BLAKE3 MAC over all of them, computed with the vault's route MAC key in the
same length-prefixed, domain-separated shape as `gateway_routes`.

A row whose MAC does not verify is treated as **absent**: tampering with
`vault.db` downgrades to "ask the user again", never to "silently trusted".
`origin::list` reports the count of tampered rows rather than hiding them.

Approval is per `(origin, provider)`. A different host, a subdomain of an
approved host, or the same host for a different provider is a different
decision. Changing the project's `SUPABASE_URL` requires re-approval.

Recording an approval needs the route MAC key, which needs an unlocked
vault — the same bar as creating the route itself.

### D5. An existing custom base URL downgrades rather than being overwritten

For a fixed-origin provider whose base-URL variable already holds a value
that is not the manifest origin, the configurability downgrades to
`NeedsOriginConfirm` on the **existing** destination, with a limitation
naming both endpoints. Tethra does not silently re-point a project's
traffic; it asks whether to keep sending it where it already goes.

A value equal to the manifest origin is not a customisation and stays
`Automatic`. A value pointing at `127.0.0.1` is Tethra's own previous
writing and is excluded from the signal entirely — otherwise Tethra's
output became Tethra's evidence for `Confirmed` (`ZFT-025`).

### D6. A value's shape is evidence; a variable name alone is not

The manifests have always carried each provider's **public** key-format
patterns and detection never consulted them, so the placeholder filter was
the only check a value ever got: `OPENAI_API_KEY=abcdefgh` reached the
auto-select threshold (`ZFT-027`).

A value matching the published format promotes a lone name-match to
`Confirmed`. A value matching **no** known format holds a lone name-match
at `Possible`, below the threshold `Selections` auto-includes at. A
non-match never *refuses* — a provider may issue a format the manifest
predates, and refusing on that would be worse than the false positive. The
value is tested and dropped; nothing about it is stored or rendered.

## Consequences

* A Supabase user answers one extra question the first time, and never
  again for that project URL. That is the intended cost.
* A user behind a corporate LLM gateway is asked instead of silently
  re-pointed. Some will find the prompt surprising; being re-pointed
  without being told is worse.
* `--yes` in CI against a repository with a project-chosen origin now
  configures the built-in providers and reports the custom one as not
  approved, with the exact `--allow-origin` line to add. This is a
  deliberate behaviour change for automated callers.
* The approval is only as good as the disclosure. A user who approves a
  destination they should not have is not protected by this mechanism; the
  controls are the default of no and the disclosure at the decision point.

## Alternatives considered

* **Allowlist by suffix** (`*.supabase.co`). Rejected: a wildcard is
  exactly the "no wildcard origins" rule the threat model already states,
  and `attacker.supabase.co` is registrable on many such services.
* **Approve at first traffic instead of at setup.** Rejected: by then the
  credential has already been forwarded once.
* **Keep the pre-filled origin but require a second click.** Rejected: a
  pre-filled, pre-checked control is the shape that produced the finding.
  The default has to be off.
