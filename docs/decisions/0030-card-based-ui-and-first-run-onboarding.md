# ADR 0030 — A card-based interface and a one-folder first run

Status: accepted
Date: 2026-08-02
Amends: ADR 0022 (zero-friction API tracking), ADR 0029 (projects-first live
activity)
Preserves: ADR 0019, ADR 0020, ADR 0023, ADR 0024, ADR 0025, ADR 0026,
ADR 0027, ADR 0028

## Context

Two problems, both product-level rather than technical.

**The marketing site described a product that did not exist.** The dashboard
illustration at `landing/index.html` was a hand-drawn HTML/SVG mock with
invented figures — 18,492 requests, 12 tracked projects, $418 observed cost,
a request-volume chart, a status feed. The Activity screen it depicted rendered
a `<dl>` of seven figures and four `<ul>`s of sentences, and had no chart on it
at all. `ActivityChart.tsx` existed and was mounted in exactly one place, the
project page. Someone who downloaded Tethra because of that illustration did
not get it.

**There was no first run.** After `vault_create` the user landed on an empty
dashboard whose only affordance pointed at `TrackFlow`, while the documented
path (ADR 0029) started from a project. Grepping `apps/desktop/src` for
`onboard|welcome|first-run` matched one code comment. Reaching live activity
meant: create a project → type a filesystem path into a plain text input (no
picker, though `@tauri-apps/plugin-dialog` was already a dependency and used
two screens away) → open the project → choose the folder again → add
credentials by hand, re-entering keys Tethra had already found and listed but
offered no way to store.

Underneath both: `styles.css` was 2,714 lines of four redesigns layered rather
than replaced. `button`, `table`, `.badge` and `.metric-grid` were each
declared two or three times and only the last one counted; `.stack` was used
47 times with no rule behind it, and `button.secondary` likewise.

`PRODUCT_SPEC.md:451` says not to spend time on visual polish or a custom
design system, and `CLAUDE.md` ranks visual appearance last of seven
priorities. That guidance was written when the risk was gold-plating an
otherwise plain tool. The situation here is different: the interface had
stopped communicating what the product does, and the gap between the promise
and the screen was itself a correctness problem. This ADR records the
departure, taken on the user's explicit instruction, under the scope hierarchy
in `CLAUDE.md` (the session prompt defines active scope).

## Decision

**1. One design layer.** `styles.css` is a single stratum: every selector
appears once, the black/Apple-blue token set is the only palette, and spacing,
type and z-index scales exist as tokens. Dead layers removed, dead classes
(`.stack`, `button.secondary`) given real rules. 2,714 → ~1,900 lines.

**2. Cards where a user is scanning; tables where a user is reading rows.**
Projects, providers and credentials are card grids carrying the figures that
answer "which of these is busy, and is anything wrong". Usage records, pricing,
rotation history and delivery history stay tables — they are genuinely tabular
and are read a row at a time.

**3. The dashboard shows the four figures the site promises**, plus the
request-volume chart and an activity feed, from real data.

**4. First run is one folder pick.** `Welcome.tsx` creates the project from the
folder name, previews, discloses and links, in one screen. It is shown when the
vault has no projects and the user has not navigated elsewhere.

**5. A detected credential can be stored from where it is shown.** The
detection row seeds the normal credential form and is resolved to `completed`
against the credential that results.

## What this does not change

Every honesty rule holds, and the new surfaces are bound by them:

- **Absent is not zero.** The dashboard chart sums per-project series, and sums
  **only `requests` and `errors`** — the two metrics where an absent bucket is
  a real zero (`absentMeansZero`, `ActivityChart.tsx`). Tokens, latency and
  cost are emitted as `null` and every aggregated point carries
  `cost_complete: false`, because coverage differs per project and a sum would
  present a partial figure as a total.
- **An unknown cost never acquires a dollar sign.** The cost tile goes through
  `formatCostMicros`; with no usage reported it renders the sentence and the
  lower-bound caveat is withheld, because that caveat describes a figure.
- **Provider-reported usage is never summed with observed traffic.**
- **No enum token reaches the screen.** The feed renders
  `attributionSentence(...)`, not the raw label.
- **Present tense and past tense stay separate** (ADR 0025) — the tracked-project
  section keeps "Right now" and "Previously" as distinct headings.
- **Disclosure is verbatim.** `Welcome.tsx` renders `preview.disclosure` from
  the backend unchanged, in a `<details open>` — moved, not summarised, and not
  hidden behind a click. Scope is still stated before the picker opens
  (ZFT-009), and the digest shown is the digest sent to `project_folder_link`.
- **Reauth and confirmation gates are untouched.** No destructive or
  secret-revealing action lost a step.
- **Charts keep their text equivalent.** `ActivityChart` retains `role="img"`,
  `<title>`/`<desc>` and the `.visually-hidden` table. `Sparkline` is
  deliberately *not* a chart — it states its range, total and peak in its
  accessible name and the exact figures sit on the card beside it.
- **Colour never carries meaning alone.** Every status dot sits next to a
  phrase.

## Provider marks

The provider library needed per-provider identity, and the repository had
none: no `logo`, `icon` or `brand` field in any of the 21 manifests and no
vendor artwork anywhere in the tree. Fetching marks at runtime is not
available — Tethra talks only to providers the user selected and official
documentation sites.

`visuals/ProviderMarks.tsx` is therefore a registry keyed by manifest `id`
holding each vendor's brand colour, rendering a brand-tinted monogram tile, with
a `path` slot for an official logo. **No logo is traced or approximated.** A
wrong mark misrepresents someone else's brand, so until a vendor's own SVG is
taken from their published brand kit and added to the registry, the monogram is
what ships and it is what the tests assert.

## Alternatives considered

- **A gateway-level series command in Rust.** Correct architecture, and the
  right long-term answer. Not taken now because the aggregation involved is the
  sum of two count metrics whose zero-fill semantics are already settled, and
  adding a command plus its contract test was a larger change than the surface
  needed. Recorded as the preferred future fix; if the dashboard chart grows
  any metric beyond requests and errors, it becomes required rather than
  preferred.
- **Leaving `styles.css` alone and appending a fifth layer.** Lower risk per
  change and unbounded cost afterwards; the duplicate-definition problem was
  already causing silent misbehaviour (`.finding`'s severity bar had been
  flattened from 3px to 1px by a later `border` shorthand).
- **Bundling traced vendor logos.** Rejected: see above.

## Consequences

- `docs/UI_MAP.md` and `docs/MANUAL_UI_TEST_PLAN.md` describe strings this
  change moved; both are updated, and both will keep drifting on any copy
  change. That is a known cost of verbatim-label documentation.
- The dashboard now issues one `project_activity` call per project with traffic
  in the window, in addition to the summary. Local SQLite, and each failure is
  isolated — a project whose series cannot be read is dropped from the chart
  rather than charted as a quiet period.
- Two onboarding implementations still exist. `TrackFlow` remains reachable at
  Settings → Tracking setup for repair and diagnosis, which is what its
  seven-phase state machine is genuinely good at, but it is no longer a second
  front door: nothing routes a new user to it.
