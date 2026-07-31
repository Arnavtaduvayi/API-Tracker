# Detection coverage

What Tethra can detect from a selected project folder, what it can
configure, and what it deliberately does not do. Implementation:
`crates/tracking/src/detect.rs`; bounds pinned by
`crates/tracking/tests/bounds.rs`.

## Providers

Measured from `provider-manifests/` and pinned by
`crates/core/tests/provider_manifests.rs`, which asserts these counts
against literals — so the numbers here cannot drift away from the tree
without failing the build:

* **21** provider manifests in total
* **13** are *trackable*: they declare a `[gateway]` section naming the
  base-URL environment variable their official SDK reads
* **8** are detected and honestly labelled **unsupported**: their SDK
  exposes no base-URL environment variable, so Tethra cannot observe them
  this way

### Trackable — configured automatically (11)

`openai`, `anthropic`, `groq`, `together`, `cerebras`, `fireworks`,
`perplexity`, `cohere`, `replicate`, `langsmith`, `google-gemini`.

Each has a fixed origin compiled into its manifest, so the route
destination cannot be influenced by the project being scanned and needs no
confirmation (ADR 0024 D1).

### Trackable — needs one destination confirmation (2)

`supabase` and `azure-openai` have no fixed origin: every account gets its
own host. The origin is read from the project's own configuration, so it is
**detection evidence, not authorization**: it is shown verbatim with its
source file and variable, and requires an explicit approval that defaults
to off (ADR 0024). Approving one exact origin never approves another.

### Detected, not trackable (8)

`stripe`, `github`, `mistral`, `deepseek`, `xai`, `openrouter`,
`huggingface`, `aws-bedrock`.

These are listed on the review screen with a per-provider explanation
rather than being hidden. Two of them deserve their reasons stated:

* **`aws-bedrock`** can never work through a loopback route in its SigV4
  mode, because the signature covers the `Host` header.
* **`huggingface`** documents `HF_INFERENCE_ENDPOINT`, but the current
  `huggingface_hub` client demonstrably does not read it. A route that
  never carries traffic is worse than an honest "not supported yet".

### What is NOT detected

Anything without a provider manifest has no provider identity here. It is
**not** invisible: credential-shaped variables Tethra cannot attribute are
listed explicitly as "not recognised", with their name and file, and are
counted in the coverage headline. A screen that says *N API integrations
found* accounts for every one of them. (Before the remediation, a 30-API
project showed four providers under a heading reading `Detected:` and
twenty-six credentials appeared nowhere at all — audit finding `ZFT-010`.)

Adding a provider is manifest work (`provider-manifests/*.toml`), not code.
The one rule that cannot be enforced by CI: a manifest can name a base-URL
variable no SDK actually reads. Nothing in the test suite can tell a
fabricated variable name from a real one, so every `[gateway]` section must
be verified against the SDK's own source and the source recorded in a
comment — see `CONTRIBUTING.md`.

## Signals and confidence

Five independent signals are fused:

* **S1** — a known secret environment-variable *name* present with a
  non-placeholder value. The value is checked for placeholder-ness and
  never read further, stored, or displayed.
* **S2** — an SDK dependency in `package.json`, `requirements.txt`, or
  `pyproject.toml`.
* **S3** — a base-URL variable already present by name.
* **S4** — a Tethra credential for that provider already assigned to the
  project.
* **S5** — a lockfile or configuration-file mention.

```text
Confirmed  = (S1 or S4) and (S2 or S3)     the project has the key AND the code
           | S1 and S4                      the key in .env matches an assigned credential
Likely     = exactly one of S1, S2, S4
Possible   = only S3 or only S5
```

Confirmed requires two independent signal classes, because Confirmed is
the bar for changing a user's files with no interaction. A dependency
alone is Likely — plenty of projects carry an unused SDK.

Prior decisions recorded in `stack_preferences` adjust one step up
(previously confirmed) or down (previously dismissed), reusing the
existing learning loop rather than inventing a second one.

In the review screen, Confirmed and Likely rows arrive pre-selected,
Possible rows unselected, and unsupported rows informational. Unsupported
providers never block supported ones.

## Files read

* Every `.env*` file the existing `envgov::discover` inventory finds
  (depth ≤ 6, skip-dirs `.git`, `node_modules`, `target`, `dist`,
  `build`, `.venv`, symlinks never followed).
* `package.json`, `requirements.txt`, `pyproject.toml` — dependencies.
* `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` — mentions only.
* Framework and CI config files that `stackdetect` already reads.
* Presence checks only for `docker-compose.yml` / `compose.yaml`,
  `Dockerfile`, `.devcontainer`.

Vault-side, it also reads the provider names of credentials already
assigned to the project. Never their values.

## Hard bounds

Every one of these is a test, not a promise. Where a bound's *fixture* is
platform-specific, that is said explicitly rather than left for a reader to
discover (audit finding `ZFT-VAL-14`).

* **Nothing the project controls is executed.** The automatic scan path
  spawns no subprocess at all: repository status comes from a byte reader
  (`crates/core/src/gitsafe.rs`), not from `git`. Pinned by
  `crates/core/tests/git_execution_canaries.rs`, which plants an
  executable canary for `core.fsmonitor`, hooks, clean/smudge filters,
  textconv, external diff drivers, aliases, pager, editor, credential
  helper, submodule update, a nested hostile repository, a hostile *global*
  config and a hostile *environment* — and additionally proves each canary
  is capable of firing by running the unprotected equivalent. See ADR 0023.
* Reads only under the selected folder, canonicalized first — by **every**
  reader. `crates/tracking/tests/scan_bounds.rs` covers a symlinked
  `package.json`, `requirements.txt`, `pyproject.toml` and marker file,
  each with a control proving a real in-folder file is still read. The
  symlink *fixtures* are `#[cfg(unix)]` because creating a symlink on
  Windows needs a privilege hosted runners may lack; the containment code
  is not platform-conditional.
* Refuses the filesystem root, the home directory, and the directory
  containing home directories — including via a path that canonicalizes
  to one of them, on every platform (`HOME`, `USERPROFILE`,
  `HOMEDRIVE`+`HOMEPATH`).
* Depth ≤ 6; a file at depth 7 is invisible.
* 256 KiB per file, **checked on the directory entry before the file is
  opened**. An oversized file stays in the inventory marked `oversized`
  with zero parsed entries — its bytes never enter memory.
* Bounded in more than depth: files, directories, total bytes and wall
  clock. A pass that stops early reports *why*, and is never presented as
  a complete scan.
* Every file the scan touches lands in exactly one accounting bucket —
  read, oversized, outside-the-folder, or not-valid-text. A non-UTF-8 file
  is counted, not silently dropped.
* Parse-only. `.env` content is never executed or interpolated — a
  fixture containing `$(touch pwned)` proves the file is not created.
* No network calls; a source-level test asserts the detection module
  contains no socket, resolver, or HTTP-client construct.
* Evidence carries variable names, file paths, dependency names, and
  provider ids. A canary test serializes every fixture's detection and
  asserts no secret value appears.

### Bounds a hardlink defeats

A **hardlink** inside the folder pointing at a file outside it is
indistinguishable from an ordinary file at the filesystem level, and is
read. Only variable names and dependency names leave the parse, so the
consequence is a detection the user did not expect, not a value
disclosure. Recorded in `KNOWN_LIMITATIONS.md`.

## The one value-read exception

For a custom-origin provider (manifest `[gateway].origins = []`), the
value of its manifest-declared **non-secret** base-URL variable may be
read to infer an origin — `SUPABASE_URL` today. That value is:

1. validated by the unchanged `routes::validate_origin` plus the SSRF
   policy (https only, port 443, no userinfo, no loopback/private/
   link-local/metadata addresses);
2. displayed verbatim with "traffic will be forwarded only to this exact
   address";
3. never auto-applied — it requires an explicit confirmation.

Secret-classified variables are never value-read for origin inference. A
test plants a URL in `SUPABASE_SERVICE_ROLE_KEY` and asserts it never
surfaces. Values that fail validation are counted, never shown as
confirmable.

## Known gaps (deliberate, this milestone)

* Source-import scanning (`import openai` in arbitrary source files).
* `Cargo.toml`, `go.mod`, `Gemfile`, and nested/monorepo sub-package
  manifests — only root manifests are read (O-22-6).
* Host sniffing beyond the compiled-in host table.
* Auto-adding providers that have no manifest.

Scanning a monorepo sub-package works today by selecting that
sub-package's folder: a project may hold several tracking setups, one per
folder.
