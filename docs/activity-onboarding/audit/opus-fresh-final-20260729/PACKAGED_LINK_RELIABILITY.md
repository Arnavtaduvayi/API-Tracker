# The intermittent packaged-link failure — root cause

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`.

**Result: it is not flakiness, and it is not harness-only. It is a real
ordering defect in `tethra gateway install`.** The remediation's recorded
disposition — *"this is a HARNESS reliability defect, not a product defect"*
(`POST_FINAL_REAUDIT_EVIDENCE.md:511-513`) — is **wrong** and should be
corrected.

## 1. The failing check

Two premise corrections first: the check lives in
`scripts/gateway_validate_macos.sh` (not the tracking harness), and it is a
`grep` over a project `.env`, not a count over `gateway_project_links`.

`gateway_validate_macos.sh:441-445`:

```sh
"$CLI" gateway link --project app --route openai --env-file "$PROJDIR/.env" --yes
grep -q "OPENAI_BASE_URL=http://127.0.0.1:$PORT/p/" … || bad "base url not written"
grep -q "OPENAI_API_BASE=http://127.0.0.1:$PORT/p/"  … || bad "alias not written"
grep -q "NO_PROXY=127.0.0.1,localhost,::1"           … || bad "NO_PROXY missing"
grep -q "tethra-gateway route: openai"               … || bad "marker missing"
```

`$PORT` is set at `:418` from `tethra --json gateway status` — the **live bound
port**.

Observed once, run `30413022801`, head `9844c49` (a docs-only diff from the
passing `4ee7494`):

```
PASS  gateway is listening (port 49209), identity-verified via status
…
FAIL  base url not written
FAIL  alias not written
PASS  NO_PROXY written
PASS  marker comment written
PASS  existing OPENAI_API_KEY preserved
=== PACKAGED MACOS RESULT: 55 passed, 2 failed ===
```

## 2. It was never a "partial link"

`envlink.rs:718-865` builds **one** `EnvDocument`, sets the base-URL vars, then
`NO_PROXY`, then renders the whole file; `apply_link` writes it with a single
`envgov::atomic_write` (`:622-628`). A state where the marker and `NO_PROXY`
land but the base URL does not is **structurally impossible**.

The base URL has exactly one variable component (`envlink.rs:536-540`):

```rust
format!("http://127.0.0.1:{port}/p/{link_slug}/{}{}", req.route_prefix, base_path(&provider_id))
```

And the harness's own next step proves the `.env` *did* hold a well-formed
URL: `:475` re-extracts the slug with a **port-independent** regex, and the
subsequent curl got a real 401 from OpenAI. So the file contained
`http://127.0.0.1:<X>/p/<slug>/openai/v1` with `X ≠ 49209`. **A port
mismatch.**

The documented rule-out is circular: `POST_FINAL_REAUDIT_EVIDENCE.md:496-498`
excludes a port mismatch because "both runs report the same value in `gateway
is listening (port N)` and in `link base: …:N`" — but those are the *same
shell variable* (`:418` and `:476`). They can never disagree. And because
`:475` rebuilds the URL from the live port plus a port-independent slug, the
harness silently repaired the broken URL before curl ran, so the downstream
passes are not evidence of health either.

## 3. Root cause — confirmed by direct source reading

`apps/cli/src/gateway_cmd.rs:398-419`:

```rust
let mut config = store::load_config(vault.connection())?;
if config.port.is_none() { … config.port = Some(ephemeral); }
let port = config.port.expect("just ensured");

let report = lc.install(&source, force)?;          // ← plist + bootstrap + kickstart: SERVICE STARTS HERE
print_install_report(&report);
config.enabled = true;
store::save_config(vault.connection(), &config)?;  // ← the port is COMMITTED HERE, afterwards
```

The plist argv (`lifecycle/macos.rs:124-129`) is `gateway serve --service
--data-dir <dir>` — **no `--port`**. The service therefore resolves its port
itself (`gateway_cmd.rs:1062`):

```rust
let configured = port.or_else(|| store::port_hint(&data_dir)).unwrap_or(0);
```

`store::port_hint` (`store.rs:46-49`) swallows **every** failure into `None`,
with the conflation stated in its own doc comment. The database is WAL
(`db.rs:1212`), so a reader starting before the installer's commit does not
block — it gets the pre-write snapshot with `port = NULL`, immediately and
silently. `configured = 0` ⇒ `bind(0)` ⇒ a *different* ephemeral port. And
`serve_service_mode` **never persists the port it actually bound**, unlike
foreground `serve`, which does with an explicit rationale
(`gateway_cmd.rs:974-984`):

> "Persist the port we actually got… A failure here is NOT cosmetic — the next
> run would bind a different random port and every linked SDK would get
> connection-refused."

**Elimination proof:** if `port_hint` returns `Some(P)`, `run_as_service`
(`service.rs:556-618`) retries `Service::start(data_dir, P)` with the *same*
port forever on `EADDRINUSE` — it never falls back to 0. So a bound port ≠
persisted port is reachable **only** through `port_hint() == None` at boot.

### Timing evidence

Duration from `== 1-3 ==` to `PASS gateway install succeeded`:

| run | head | result | install |
| --- | --- | --- | --- |
| 30413771190 | `0c3b7d6` | pass | 0.59 s |
| 30413371301 | `db2707a` | pass | 0.62 s |
| **30413022801** | **`9844c49`** | **FAIL** | **13.38 s** |
| 30412989375 | `4ee7494` | pass | 0.51 s |
| 30412862462 | `e4c5264` | pass | 0.49 s |

The install path's only blocking loop is `gateway_cmd.rs:431-446`: 40 × 250 ms
= **exactly 10 s** of `verify_listener(data_dir, config.port)`. 13.38 s ≈ 3.4 s
of contended work plus the **full timeout**. On the failing run the persisted
port never answered its identity probe while `gateway status` simultaneously
reported a live gateway on 49209. That timeout is non-fatal
(`:447-457` prints a note and returns `Ok(())`), and the harness's
`ok "gateway install succeeded"` is exit-code-only — so it passed.

### The other two enable paths get it right

* Desktop `main.rs:2589-2599` — persists first, with the invariant stated:
  *"The stable port is chosen and persisted BEFORE the service starts (the
  service reads it from the database at boot — ADR 0019 O3)."*
* Tracking `crates/tracking/src/apply.rs:381-420` — `StepId::EnsurePort` calls
  `store::save_config` at `:399` **before** `ops.ensure_service(...)` at `:420`.

**Only `tethra gateway install` violates the invariant.** This matters for
severity: the supported zero-friction journey — the desktop Track flow and the
`tethra track .` fallback — both use the correct ordering. The defective path
is an advanced, manual command.

## 4. Product-visible? Yes. Safe recovery? Yes — but mis-signposted.

A user running `tethra gateway install` on a fresh vault can end with `.env`
pointing at a port nothing listens on; their SDK gets `ECONNREFUSED`.

What the product then tells them:

* `tethra gateway link` **does** warn about the symptom
  (`gateway_cmd.rs:1510-1521`) — but the **diagnosis and remedy are wrong**: it
  says the gateway is not running and to start it, when the gateway *is*
  running, and `gateway start` on an already-registered live service
  (`:620-633`) will not move it.
* `tethra gateway status` / `doctor` **report healthy**. `doctor.rs:216-239`
  emits findings only for `NotOurs`/`NoNonce`; `NoListener` on the persisted
  port falls through `_ => {}`. `live` is then true because the control socket
  answers (`:243-244`). `link_health` (`:604-612`) compares the `.env` against
  **`config.port`, never the live port**, so the link reads `(ok)`.
  **No code anywhere compares `config.port` to `gateway_status.port`.**
* `tethra track status` **does** catch it (`track_cmd.rs:901-913`) — it probes
  `verify_listener(data_dir, config.port)` and reports `GatewayLiveness::Down`,
  though it says "down" rather than "the port moved".

**Recovery** is `tethra gateway restart`: by then `config.port` is committed,
so `port_hint` returns it and the service binds it; the existing `.env`
becomes correct with no re-link. `unlink` restores the `.env` byte-exactly
(harness step 23 passed even in the failing run). Nothing is corrupted and no
credential is exposed.

## 5. Was it fixed? No — only instrumented

`5b35196` adds a failure-time dump (`gateway_validate_macos.sh:457-473`).

* It prints `link.log`, which carries the probe note **with the persisted port
  in the clear** — exactly the missing datum. It would confirm the hypothesis
  next time.
* `head -20` is tight; a larger `.env` would truncate the note away.
* The `.env` shape dump prints `NAME -> other value` and never the port, so it
  is useless for this hypothesis — contrary to
  `POST_FINAL_REAUDIT_EVIDENCE.md:506-510`.
* It is gated on the cumulative `fail` counter, so any earlier failure triggers
  a spurious dump.

**There is no regression test and no product fix.** Nothing in
`crates/gateway/tests/`, `crates/tracking/tests/` or `apps/cli/tests/` asserts
that the service binds the persisted port, or that install persists before it
starts.

## 6. Idempotency, transactions, readiness (as asked)

* **Idempotent:** yes. `plan_link` reuses an existing `link_slug`
  (`envlink.rs:531-535`); `apply_link` inserts only when `!existing_link`
  (`:597-604`). Duplicates are not the failure mode.
* **Transactions:** the row and restore record commit **before** any file is
  touched, deliberately (`envlink.rs:592-596`) — a crash between them
  over-describes restoration rather than under-describing it. Sound.
* **Gateway not ready:** `plan_link_as_provider_projected` **refuses** with
  *"the gateway has no persisted port yet, so a stable base URL cannot be
  written"* (`:523-529`). The link path is correct; it faithfully wrote the
  persisted port. The defect is upstream in who persisted what, and when.

## 7. CI history

`packaged-service-macos.yml`, this PR's chain (newest first):

```
0c3b7d6  success   ← audited head (docs only)
db2707a  success
9844c49  FAILURE   ← the link failure; docs-only diff vs 4ee7494
4ee7494  success
e4c5264  success
1af8edf  success
54455ee  FAILURE ┐
9117e83  FAILURE ├ probe_primitive subshell (fixed by 1af8edf)
141152d  FAILURE │
4140168  FAILURE ┘
cac469e  success   ← previously audited head
```

The `9844c49` failure is the sole unexplained one, on an unchanged product
tree — consistent with a timing-dependent race, not a code regression.

## 8. Disposition

**`NEW-02`, Medium. Not merge-blocking**, because the supported journey uses
the correct ordering and safe non-destructive recovery exists. It is recorded
as a real product defect rather than harness flakiness, with two required
corrections: the one-line reordering in `gateway_cmd.rs`, and a `doctor`
finding for `config.port != gateway_status.port` so the recovery is
signposted instead of contradicted.
