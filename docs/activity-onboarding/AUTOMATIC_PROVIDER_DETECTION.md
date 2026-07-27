# Automatic Provider Detection — Design

How Tethra decides, from one user-selected folder, which providers a
project uses, at what confidence, and what can be configured automatically.

## 1. What already exists (reuse, not rebuild)

Three independent detection signals already ship, none of which answers
"which providers does this folder use" by itself:

| Component | Location | Signal | Confidence source |
|---|---|---|---|
| Stack detection | `crates/core/src/stackdetect.rs` | `package.json` deps, `requirements.txt`, `pyproject.toml`, framework configs, workflows, Dockerfile, lockfiles, `.env*` variable **names** in the repo root | `providers::Confidence {Low, Medium, High}` |
| Env governance | `crates/core/src/envgov.rs` | `.env*` inventory: `discover(root)` (depth ≤ 6, skip dirs, no symlinks), file class (values vs template), environment classification, git status | structural |
| Secret scanner | `crates/core/src/scanner.rs` | provider key **value** patterns from manifests, known secret env-var names, entropy | manifest-declared |

Provider knowledge is centralized in `provider-manifests/*.toml`
(compiled in via `providers::MANIFEST_SOURCES`): secret env vars
(`env_vars`), detection regexes (`[[detection]]`), and — for gateway-capable
providers — `[gateway] { origins, base_path, env_vars (base-URL vars),
usage_shape }`. Host→provider mapping exists separately in
`crates/core/src/runtime/inventory.rs` (`HOST_PROVIDERS`,
`provider_for_host`). Vault-side signals: credentials already assigned to
the project (`credentials.provider`), and `credential_env_mappings`.

The gap: a fused, folder-scoped `detect_providers(folder, project)` API
with per-provider confidence and configurability. That is the new module.

## 2. New module

`crates/tracking/src/detect.rs` (crate decision in
`TRACKING_ORCHESTRATOR.md` §2). Public API:

```rust
pub struct DetectionInput<'a> {
    pub folder: &'a Path,             // user-selected, canonicalized
    pub project_id: Option<&'a str>,  // for vault-side signals
}

pub fn detect(conn: &Connection, input: &DetectionInput)
    -> Result<ProjectDetection>;

pub struct ProjectDetection {
    pub folder: PathBuf,
    pub providers: Vec<ProviderDetection>,
    pub env_files: Vec<EnvFileInfo>,      // from envgov::discover
    pub project_signals: ProjectSignals,  // docker-compose, dotenv loader, …
    pub scanned_files: u32,               // for "review what was scanned"
    pub skipped_oversized: u32,           // honesty: nothing silently capped
}

pub struct ProviderDetection {
    pub provider_id: String,
    pub confidence: DetectionConfidence,  // Confirmed | Likely | Possible
    pub configurability: Configurability,
    pub evidence: Vec<Evidence>,          // human-renderable, value-free
    pub inferred_origin: Option<InferredOrigin>, // custom-origin providers
    pub target_env_files: Vec<PathBuf>,   // where the base URL would go
}

pub enum Configurability {
    Automatic,           // manifest [gateway] with fixed origin
    NeedsOriginConfirm,  // [gateway] with origins = [] and an inferred origin
    NeedsOriginInput,    // [gateway] with origins = [] and nothing inferable
    Unsupported { reason: UnsupportedReason }, // no [gateway] section, or no base-URL var
}
```

`Evidence` is an enum (`SecretEnvVarName { var, file }`,
`SdkDependency { dep, manifest }`, `BaseUrlVar { var, file }`,
`AssignedCredential { credential_name }`, `LockfileMention { file }`,
`ConfigFile { file }`) rendered to sentences in the UI — it never carries a
secret value.

## 3. Signal fusion and confidence rules

Inputs per provider, gathered from the bounded scan:

* S1 — secret env-var name present with a non-placeholder value
  (`manifest.env_vars` ∩ discovered env files; values stay inside the
  redacting `EnvDocument`; placeholder check via
  `scanner::is_placeholder_value`).
* S2 — SDK dependency in `package.json` / `requirements.txt` /
  `pyproject.toml` (stackdetect High rules).
* S3 — base-URL variable already present (`[gateway].env_vars` name found;
  or a value whose host matches `provider_for_host` — see §5 for the value
  handling rule).
* S4 — a Tethra credential for this provider already assigned to the
  project.
* S5 — lockfile / config-file mentions (stackdetect Low rules).

Confidence:

```text
Confirmed  = (S1 or S4) and (S2 or S3)     — the project has the key AND the code
           | S1 and S4                      — key in .env matches assigned credential
Likely     = exactly one of S1, S2, S4
Possible   = only S3 or only S5
```

Rationale: "Confirmed" must justify configuring with zero interaction, so
it requires two independent signal classes. A dependency alone (S2) is
"Likely" — plenty of projects have an unused SDK installed. Prior
user decisions from `stack_preferences` (`stack_decide`) adjust one step up
(confirmed earlier) or down (dismissed earlier), reusing the existing
learning loop.

Configurability is orthogonal to confidence:

* `openai`, `anthropic` → `Automatic` (manifest origin, base-URL vars).
* `supabase` → origin is per-project: if exactly one `SUPABASE_URL` value
  in the values-class env file parses as a valid https origin
  (`routes::validate_origin` rules), emit
  `NeedsOriginConfirm { inferred_origin }` — shown pre-filled, one
  checkbox. Multiple conflicting values, or none → `NeedsOriginInput`.
* `stripe`, `github` → `Unsupported { NoConfigurableBaseUrl }` today (no
  `[gateway]` section). They still appear in the review screen, honestly
  labeled. Expanding the supported set is provider-manifest work, tracked
  in `OPEN_DECISIONS.md` O-22-5.
* A credential-shaped variable with no matching manifest at all → it is NOT
  a "provider" and gets no `Configurability` value, because Tethra has
  nothing to say about it beyond that it exists. It appears in
  `ProjectDetection.unrecognized` with its variable NAME, its file, and a
  presentation-only name hint, and it is counted in the coverage headline.
  `Unsupported { UnknownProvider }` is still in the enum for a manifest-less
  id arriving from another signal path; it is not how an unrecognised
  credential surfaces.

  This page previously promised `Unsupported { UnknownProvider }` for this
  case while `DETECTION_COVERAGE.md` said "anything without a provider
  manifest is not detected at all", and the code did the second — so
  twenty-six credentials in a thirty-API project appeared nowhere
  (`ZFT-010`). The two documents now say the same thing, and it is the
  thing the code does.

The normal workflow auto-configures `Confirmed × Automatic`. `Likely` and
`NeedsOriginConfirm` rows appear pre-selected in the review screen;
`Possible` rows appear unselected. `Unsupported` rows are informational.
Unknown providers never block supported ones.

## 4. Scan boundaries (hard rules)

Identical in spirit to the existing scanners, enforced in the new module
and pinned by tests (`TEST_PLAN.md` §3):

* Read only under the selected folder; canonicalize it first; refuse to
  scan filesystem roots and home directories (`/`, `/Users/<name>`, `~`)
  with an explanatory error — a misclick must not become a broad scan.
* Reuse `envgov::discover` bounds: depth ≤ 6, skip dirs
  (`.git`, `node_modules`, `target`, `dist`, `build`, `.venv`, …), never
  follow symlinks out of the folder.
* Reuse stackdetect's `MAX_FILE_BYTES = 262_144` per manifest/config file;
  count and report skips (`skipped_oversized`).
* Parse only: never execute project files, `.env` files, or package
  scripts; `EnvDocument::parse` never interpolates. This bound is
  load-bearing and was NOT met before the remediation: detection asked
  `git` four questions per file, and git executes programs named by the
  scanned repository's own config, so a hostile `core.fsmonitor` ran during
  `--dry-run` (`ZFT-001`). The automatic path now spawns no subprocess at
  all — see ADR 0023 and `crates/core/tests/git_execution_canaries.rs`.
* No persistence of application payloads; evidence is names, files, and
  provider ids only.
* No network access during detection. Nothing leaves the machine.

## 5. The one value-read exception

Detection is name-based except for a single, narrow value rule: for a
custom-origin provider (manifest `[gateway].origins = []`), the value of
its declared base-URL variable (e.g. `SUPABASE_URL`) may be read from the
`EnvDocument` to infer the origin — the same class of value `envlink`
already records as prior state under `prior_value_is_recordable` (an
http(s) URL without userinfo). The value is validated with the full
`routes::validate_origin` + SSRF policy before it is ever shown or used,
is displayed verbatim for confirmation ("Traffic will be forwarded only to
this exact address"), and is never treated as a secret because the
manifest classifies these variables as non-secret base-URL vars (disjoint
from `env_vars`). Secret-classified variables are never value-read by
detection.

## 6. Where results go

* Transient: `ProjectDetection` feeds the review screen / CLI plan
  directly.
* Persisted: a JSON summary (provider ids, confidence, configurability,
  evidence kinds — no values) is stored on the tracking setup row
  (`TRACKING_ORCHESTRATOR.md` §5, migration v15) so `track status`,
  re-scans, and diagnostics can diff against the last accepted detection.
* Inventory: confirmed-but-unsupported providers may seed
  `observed_api_services` rows with the already existing (currently
  unused) `ServiceSource::RepositoryDetected`, so the dashboard can show
  "detected in the repo, not yet observable" honestly. This is optional
  scope (Phase 4 in `IMPLEMENTATION_PLAN.md`).

## 7. Gaps deliberately not closed in this phase

* Source-code import scanning (`import openai` in arbitrary files),
  `Cargo.toml`, `go.mod`, `Gemfile`, monorepo sub-package manifests —
  stackdetect reads only root manifests today. Extending it is
  incremental, manifest-driven work; the fusion layer is built to absorb
  new signals without API change. (O-22-6.)
* ML or heuristic host sniffing beyond `HOST_PROVIDERS`.
* Auto-adding providers with no manifest.
