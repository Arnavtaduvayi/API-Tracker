# Detection Evidence — Independent Audit of PR #16

All results below were produced by executing the **packaged** helper
(`Tethra.app/Contents/MacOS/tethra`) with `PATH` stripped and an isolated
`HOME`/`TETHRA_DIR`, or by a reviewer running the compiled crate directly.
`detect.rs` (697 lines) and `stackdetect.rs` were read in full.

---

## 1. Provider coverage — the ceiling on everything else

```
$ tethra provider list
ID         NAME       SECRET ENV VARS                        PATTERNS
openai     OpenAI     OPENAI_API_KEY,OPENAI_ADMIN_KEY        3
anthropic  Anthropic  ANTHROPIC_API_KEY,ANTHROPIC_ADMIN_KEY  3
github     GitHub     GITHUB_TOKEN,GH_TOKEN,…                2
stripe     Stripe     STRIPE_SECRET_KEY,STRIPE_API_KEY,…     3
supabase   Supabase   SUPABASE_SERVICE_ROLE_KEY,…            2
```

`provider-manifests/` holds exactly five `.toml` files. Base-URL environment
variables — the prerequisite for gateway tracking — exist for three:

* `openai.toml:49` → `OPENAI_BASE_URL`, `OPENAI_API_BASE`
* `anthropic.toml:43` → `ANTHROPIC_BASE_URL`
* `supabase.toml:33` → `SUPABASE_URL`

**Trackable providers: 3.** `github` and `stripe` are detected and honestly
labelled unsupported with accurate, specific explanations. (`ZFT-011`)

---

## 2. False positives

| Probe | Input | Result | Verdict |
|---|---|---|---|
| Name-prefix collision | `pyproject.toml` with `openai-whisper>=20240930`, `anthropic-bedrock-mock` | `openai likely Automatic`, `anthropic likely Automatic` — both auto-selected | **FAIL** (`ZFT-026`). `stackdetect.rs:191-193` uses `starts_with`, not an exact name match. `requirements.txt` (`:159-164`) matches exactly — the two parsers disagree. `openai-whisper` is offline speech-to-text and never contacts OpenAI. |
| Junk values | `OPENAI_API_KEY=abcdefgh`, `ANTHROPIC_API_KEY=not-a-key-at-all` | both `likely` + `Automatic` → auto-selected | **FAIL** (`ZFT-027`). `detect.rs:391` gates only on `scanner::is_placeholder_value`, which rejects `len < 8`, twelve English needles, template brackets, and ≤2 distinct characters. The manifests ship precise key regexes (`openai.toml:27-40`: `sk-proj-[A-Za-z0-9_-]{20,}`) that S1 **never consults**. |
| Tethra's own artifact | `OPENAI_BASE_URL=http://127.0.0.1:49723/p/abc/openai/v1` + key | `confirmed` | **FAIL** (`ZFT-025`). `detect.rs:402` registers S3 on the variable *name*; the loopback guard at `:417` suppresses only origin *inference*, not the evidence. Tethra's own prior write satisfies the second "independent signal class" that `DETECTION_COVERAGE.md:43` says `Confirmed` requires. The marker tag (`envfile.rs:22`) exists and is not consulted. |
| `node_modules` decoy | `node_modules/openai/.env` with a key | not counted | **PASS** — correctly excluded |
| Template files | `.env.example` / `.sample` / `.template` / `.dist` | never value-read | **PASS** — `detect.rs:373` skips non-`Values` classes |

**Confidence honesty:** the fusion rule (`detect.rs:583-589`) does implement the
documented formula and is not hardcoded. But the inputs are weak enough that the
labels overstate: `Likely` is reachable from one junk 8-character value or a name
collision; `Confirmed` from the user's own custom endpoint (`ZFT-012`) or
Tethra's own prior write. Separately, `detect.rs:593-609` lets a single prior
click in the unrelated stack-template feature promote a lockfile-only `Possible`
to `Likely` — crossing the auto-apply threshold.

**Confirmed detections do not require manual selection.** `Selections::defaults`
(`plan.rs:39-57`) pre-selects every `Automatic` provider at `>= Likely`; the CLI
offers one bulk "Proceed?", never a per-provider choice. The product requirement
is met — which is precisely why the false-positive findings matter.

---

## 3. False negatives

The 30-API monorepo fixture (14 MB, 8 `.env*` files, two workspaces) yielded
**4 named, 2 configured**. Missing entirely: Groq, Mistral, Cohere, SendGrid,
Twilio, Slack, DeepSeek, Together, Perplexity, Fireworks, HuggingFace,
Azure OpenAI, Google, ElevenLabs, AssemblyAI, Pinecone, LangSmith, Replicate,
Resend, and three custom origins declared in `config/services.json`.

**Env filename probe** (each name tested alone, in isolation):

| Scanned | Not scanned |
|---|---|
| `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.test`, `.env.staging`, `.env.qa`, `.env.prod` | `env`, `.environment` |

So the misses are **provider coverage**, not file skipping. Other structural
gaps confirmed by reading the code:

* **Monorepo sub-package manifests are not read.** `stackdetect` reads root
  manifests only, so `apps/web/package.json` SDK signals are missed; a monorepo
  therefore lands at `Likely`, not `Confirmed`.
* **Config in JSON / YAML / TOML / docker-compose is not a signal.** The three
  custom origins in `config/services.json` were invisible.
* **Non-JS/Python runtimes** (the Ruby `Net::HTTP` file in the fixture) produce
  no signal.
* **Case policy is inconsistent** (`ZFT-040` sibling): S1 uses
  `eq_ignore_ascii_case` (`detect.rs:390`), S3 uses an exact map lookup
  (`detect.rs:402`). Verified: lowercase `openai_api_key` detects; lowercase
  `openai_base_url` would not.

---

## 4. Unknown APIs — not surfaced at all

```
$ tethra track <groq+mistral+cohere+deepseek+together+perplexity project> --dry-run
No trackable APIs detected in this folder.
Tethra looked at .env files, package manifests, and lockfiles (2 file(s) read, 6 levels deep).
• Using a provider Tethra doesn't support yet? See `tethra provider list`.
• Know the provider and its base URL? `tethra gateway route add` is the expert path.
                                                                    exit 2
```

`UnsupportedReason::UnknownProvider` (`detect.rs:68`) is **unreachable from
folder content** — every id entering `signals` already comes from a manifest.
`AUTOMATIC_PROVIDER_DETECTION.md:120-121` promises this variant;
`DETECTION_COVERAGE.md:18` correctly states the opposite. The documents
contradict each other and the code implements the second. (`ZFT-010`)

**Do unknowns block confirmed detections? No** — they are invisible, so they
cannot block. Genuinely-unsupported *known* providers (Stripe, GitHub) are
handled correctly: listed, labelled, sorted last (`detect.rs:679-687`), and
converted to a warning rather than an error (`plan.rs:312-331`). That control is
solid.

---

## 5. Security bounds

| Bound | Claimed | Actual |
|---|---|---|
| Parse-only, nothing executed | `detect.rs:12`, `DETECTION_COVERAGE.md:82` | **FALSE** — `ZFT-001`, arbitrary code execution via the scanned repo's `core.fsmonitor`, four spawns, during `--dry-run` |
| Reads only under the selected folder | `DETECTION_COVERAGE.md:73` | **FALSE for manifests** — `ZFT-002` |
| Symlinks never followed out of the folder | `:80` | **FALSE for manifests** — true for `.env` only |
| 256 KiB per file, never silently dropped | `:78` | **FALSE** — `ZFT-003`, 234 MB read → 1.92 GB RSS, reported as `0 file(s) read` |
| Refuses `/` and the home directory | `detect.rs:195-242` | **TRUE** — covers `HOME`, `USERPROFILE`, `HOMEDRIVE`+`HOMEPATH`, canonicalizes before comparing, refuses root-level `Users`/`home`. Three passing tests, one with a proper anti-vacuity guard. Minor gaps: `/var/home` (Fedora Silverblue) and `/export/home` are not recognised as home containers. |
| Depth cap | 6 levels | **TRUE** |
| File count / total bytes / wall time cap | — | **ABSENT** — `ZFT-028`: 300 `.env` files ⇒ 16.5 s; 2000 ⇒ 39.9 s. Up to 4 git spawns per discovered file, each with a 30 s timeout. `SKIP_DIRS` covers 6 names; `vendor`, `Pods`, `.next`, `.cache`, `__pycache__`, `.pnpm-store` are all walked. |
| Binary / non-UTF-8 handling | — | Dropped with **no counter increment** and no binary sniff (`ZFT-040`) |

**Symlink mechanics, precisely.** `envgov::discover` uses `entry.file_type()`
from `read_dir` (does not follow) and skips anything neither `is_dir()` nor
`is_file()` — so symlinked *directories* are never traversed, including ones
pointing inside the project (safe, mildly over-strict). `detect::read_bounded`
applies both `symlink_metadata` refusal **and** canonicalize-under-root —
correct. `stackdetect::read_bounded` applies **neither**. A selected folder that
is itself a symlink is fine (`canonicalize` at `detect.rs:331` resolves first).
A **hardlink** named `.env` pointing outside is read (names only) — hardlinks
have no target path for canonicalize to catch.

Residual, SUSPECTED: `read_bounded` is TOCTOU-shaped — it stats, canonicalizes,
then re-opens **by path**. The correct fix is open-then-`fstat` on the descriptor.

**Executing configuration:** no interpreter is invoked on scanned content and no
config file is sourced — but git *is* spawned, which is the `ZFT-001` vector.

**Gitignored files ARE scanned** — verified: a `.gitignore`d `.env` and
`secrets/.env.production` both produced detections. This is the **correct**
behaviour (`.env` is normally gitignored; skipping it would remove the primary
signal), git is consulted only to *label* files, never to filter them. But
**neither document states it**, and `EnvFileSummary` collapses
`GitStatus::{Tracked, Ignored, Untracked, NotInRepo}` into a single
`git_tracked: bool` (`detect.rs:356`), losing the `Untracked` distinction that
`envgov.rs:32-41` documents as *"one `git add` from leaking"*.

---

## 6. Secret leakage — clean, with one memory-hygiene gap

Traced every read. `.env` bytes flow `read_to_string` → `EnvDocument::parse` →
per-entry `SecretString` (redacting `Debug`/`Display`/`Serialize`,
zeroize-on-drop, `secret.rs:22-77`). `expose()` is called exactly twice:
`detect.rs:391` (placeholder check, result discarded) and `detect.rs:416` (origin
inference).

Nothing escaping the crate carries secret material: `Evidence` holds only names
and paths (`detect.rs:88-112`); `ProviderDetection` / `ProjectDetection` derive
`Serialize` over `String`/`bool`/enums only. No `println!`, `tracing` or `log`
anywhere in `detect.rs`.

**The documented "single value-read exception" is genuinely bounded.** It is
gated on `gw.origins.is_empty()` — Supabase only, whose `env_vars =
["SUPABASE_URL"]` is disjoint from its secret vars — and
`routes::validate_origin` (`routes.rs:66-115`) rejects non-https, non-443,
userinfo, and everything the SSRF policy denies before anything is stored.
Failures increment a counter and discard the value. This control is solid.

Confirmed by test `detect.rs:315 serialized_detection_never_contains_a_value`,
which has both a canary negative control **and** a positive control.

**Gap (LOW):** the raw `String` at `detect.rs:270` and `envgov.rs:182` holds full
plaintext secrets and is dropped without zeroing, contra `CLAUDE.md`
("Minimize how long decrypted values remain in memory").

**Honesty nit:** the evidence line reads *"Found ANTHROPIC_API_KEY in .env (value
not read)"* while the diff immediately below renders `ANTHROPIC_API_KEY=sk-a…al`
— a redacted form of the value, which required reading it. The statement is
accurate scoped to *detection signal derivation*, but sits adjacent to evidence
that the value was read. Worth rewording.

---

## 7. Custom origins and user-customized base URLs

* **Supabase (origin inference):** works, and reads the value to derive the
  origin — `create routes: supabase → https://abcdefgh.supabase.co`. The origin
  is displayed unredacted (it reveals the user's project ref; minor).
* **Conflicting origins:** two different `SUPABASE_URL` values correctly downgrade
  to `NeedsOriginInput` with *"Multiple conflicting project URLs were found; pick
  one"* (`detect.rs:642-649`). Good.
* **User-customized OpenAI/Anthropic base URL:** silently re-pointed to the
  manifest origin, and the customization *raises* confidence — `ZFT-012`, HIGH.
* **Origin provenance:** an origin read from repo content is auto-confirmed
  despite the documented explicit-checkbox gate — `ZFT-004`, HIGH.

## 8. Multiple credentials / ambiguity

For **origins**, ambiguity is handled well (above). For **secrets**, there is no
disambiguation at all: two different `OPENAI_API_KEY` values in `.env` and
`.env.production` produce two evidence items and two target files, with no
conflict signal and no per-provider choice. `credential_candidates` lists vault
names but nothing selects among them. The user is **not** forced to disambiguate
provider-by-provider — one blanket "Proceed?" covers everything — which is the
product requirement, but the silent merge is undocumented.

**Monorepo merge:** `apps/web/.env` and `apps/api/.env` merge into **one**
`openai` detection with both files as targets, so a single accept rewrites both
sub-projects. `DETECTION_COVERAGE.md:116-118` honestly documents the workaround
(select the sub-package folder); the silent cross-sub-project merge is not
documented. All sub-packages share one route id (`ZFT-005` sibling), so traffic
from `web` and `worker` is indistinguishable.
