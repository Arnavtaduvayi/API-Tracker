# Known limitations

Stated plainly, because a tracking product that overclaims coverage is
worse than one that admits its edges.

## Coverage

* **Only traffic whose base URL points at Tethra is observed.** Anything
  that constructs its own base URL in code, uses a different environment
  variable, or runs somewhere the edit didn't reach is invisible. An
  empty activity view is never evidence of zero provider usage.
* **Locally observed traffic is never summed with provider-reported
  usage.** They are different evidence classes and appear in separate,
  labeled places.
* **Cost is an estimate and a lower bound.** Cache-read tokens are
  excluded from the estimate, so a prompt-cached workload's real spend is
  higher than shown. It is labeled estimated everywhere and never
  asserted as a bill.

## Providers

* **Only providers with a `[gateway]` manifest section can be
  configured**: OpenAI and Anthropic automatically, Supabase with one
  origin confirmation.
* **Stripe and GitHub are detected but not observable this way.** Their
  SDKs do not read a base-URL environment variable. They appear in the
  review screen with that reason stated. Expanding this is
  provider-manifest work gated on verifying each SDK's actual behavior
  against official documentation — never an assumption (O-22-1).
* **Providers with no manifest are not detected at all.**

## Detection

* Only the **selected folder** is scanned — never the whole machine.
  Depth is capped at 6, per-file reads at 256 KiB, symlinks are never
  followed out of the folder, and nothing is executed.
* **Root manifests only.** `Cargo.toml`, `go.mod`, `Gemfile`, and nested
  monorepo sub-package manifests are not read yet (O-22-6). Selecting the
  sub-package folder directly does work — a project may hold several
  tracking setups, one per folder.
* **No source-import scanning.** `import openai` inside a source file is
  not a signal.
* Detection can be wrong in both directions: an unused SDK produces a
  "Likely" row, and an unusual configuration can produce nothing. Both
  are visible and correctable in the review screen.

## Environments Tethra cannot track

* **Docker / Compose projects.** A container sees neither the host's
  `.env` change nor the host's `127.0.0.1`. Tethra detects a compose file
  and diagnoses this; it does not support tracking a containerized
  project.
* **Remote development / devcontainers.** Same reason; flagged as a
  possible cause, labeled possible rather than certain.

## Platforms

* **macOS** is the validated platform. See `PACKAGED_VALIDATION.md` for
  exactly what was executed and what was not.
* **Linux** — the systemd-user lifecycle is implemented and unit-tested
  against a mock runner, and sidecar bundling is configured identically,
  but **no packaged Linux end-to-end run has ever been performed**. No
  Linux behavior is claimed.
* **Windows** — the HKCU Run-key lifecycle is **compile-validated only**
  and has never been executed. The supported mode is foreground tracking.
  **Credential attribution is structurally unavailable on Windows**: there
  is no control channel, and SI-21 refuses a TCP fallback rather than
  weakening how the key travels.

## Signing

Builds are **unsigned**. Gatekeeper may refuse the background service on
a freshly downloaded app. When that happens Tethra detects the specific
failure and offers foreground tracking, with its honest limitation:
tracking pauses when Tethra closes. Signing and notarization remain a
release blocker for public builds and require Apple Developer ID
credentials that are not configured in this repository — the one
genuinely external dependency.

## Security residuals (unchanged, carried forward)

* Any local process can use the loopback port; the service is a standing
  local egress relay to the registered providers (GW-11). Disclosed at
  consent time.
* While attribution is on, the matching key is resident in the service
  process and is a guess-confirmation oracle over in-scope fingerprints
  (GW-6). It is dropped on vault lock by default; keep-while-locked is
  off by default and capped at 8 hours.
* A user can confirm a custom origin they did not read. The origin is
  validated (https, port 443, no userinfo, no loopback/private/
  link-local/metadata), displayed verbatim, and MAC-bound — but
  confirmation is still a human decision. Equivalent to the pre-existing
  manual origin form, now reachable from a scan.

## Verification

* `traffic_observed` requires a recorded gateway observation for the
  project at or after the setup's apply time. Pre-existing traffic never
  verifies a new setup, and a stale row that claims observation is
  downgraded on read.
* The waiting window is bounded (120 s in both surfaces). Timing out
  moves the setup to **needs attention** with a ranked diagnosis — never
  to "failed permanently", because the configuration is still live and a
  later request will still be recorded.
