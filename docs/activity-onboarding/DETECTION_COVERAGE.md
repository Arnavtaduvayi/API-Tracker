# Detection coverage

What Tethra can detect from a selected project folder, what it can
configure, and what it deliberately does not do. Implementation:
`crates/tracking/src/detect.rs`; bounds pinned by
`crates/tracking/tests/bounds.rs`.

## Providers

| Provider | Detected | Configurable | How |
|---|---|---|---|
| OpenAI | yes | **automatic** | manifest `[gateway]` with a fixed origin and `OPENAI_BASE_URL` / `OPENAI_API_BASE` |
| Anthropic | yes | **automatic** | manifest `[gateway]` with a fixed origin and `ANTHROPIC_BASE_URL` |
| Supabase | yes | **needs one confirmation** | per-project origin, inferred from `SUPABASE_URL` and confirmed verbatim |
| Stripe | yes | no | the SDK does not read a base-URL environment variable |
| GitHub | yes | no | Octokit takes a base URL in code, not from the environment |

Anything without a provider manifest is not detected at all. Adding a
provider is manifest work (`provider-manifests/*.toml`), not code; the
fusion layer absorbs new entries without an API change.

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

Every one of these is a test, not a promise:

* Reads only under the selected folder, canonicalized first.
* Refuses the filesystem root, the home directory, and the directory
  containing home directories — including via a path that canonicalizes
  to one of them.
* Depth ≤ 6; a file at depth 7 is invisible.
* 256 KiB per file; oversized files are *counted* (`skipped_oversized`),
  never silently dropped.
* Symlinks are never followed out of the folder; a symlinked `.env`
  pointing outside is not read at all.
* Parse-only. `.env` content is never executed or interpolated — a
  fixture containing `$(touch pwned)` proves the file is not created.
* No network calls; a source-level test asserts the detection module
  contains no socket, resolver, or HTTP-client construct.
* Evidence carries variable names, file paths, dependency names, and
  provider ids. A canary test serializes every fixture's detection and
  asserts no secret value appears.

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
