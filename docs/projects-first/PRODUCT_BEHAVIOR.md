# Projects-first live activity — product behaviour

What a user actually experiences, and the exact wording of each state. See
ADR 0029 for why it is built this way.

## The whole normal path

```text
Create project
Select project folder
Review one disclosure, confirm
Tracking runs; activity appears on the same page
```

Normal tabs required: **Projects only**. No terminal command, no manual provider
selection, no manual route creation, no separate tracking authorization, and the
folder is linked once.

## Project page

Sections, in order:

1. **Project header** — name, description, environments, repositories, password
   lock, created, notes.
2. **Project folder** — folder path, tracking state, last scan, and the actions
   Change folder / Rescan project / Disable tracking / Unlink folder / Advanced
   tracking diagnostics.
3. **Detected credentials** — one row per detected variable, with its value and
   attribution status.
4. **Live activity** — period selector, Refresh, last-updated, summary cards,
   chart, cost coverage, detected APIs, filters, recent requests.
5. **Credentials** — the project's real vault credentials, unchanged.

## Before a folder is selected

The scope is stated **before** the picker opens:

> Tethra reads dependency and environment files in the folder you choose, to find
> which APIs the project uses. It reads variable *names*, never their values,
> never runs your code, and never looks outside the folder you pick. Nothing is
> uploaded.

Then one button: **Select project folder**.

## After the folder is chosen

Tethra scans it and shows one review block containing the backend's own
disclosure — generated from the plan, so it cannot describe less than the plan
will do. It names:

* that request metadata is recorded locally and bodies are never stored;
* that a local helper will run in the background, listening only on this
  computer;
* how many known API destinations will be registered;
* exactly which project files will be edited, and that prior values are recorded
  encrypted so it can be undone;
* how many credential variables were seen by name only;
* that nothing is sent to Tethra and the folder can be unlinked.

One confirmation — **Start tracking this folder** — applies it. That confirmation
carries a digest of what was reviewed; if the folder or configuration changed in
between, it is refused with:

> this project's folder or configuration changed since it was reviewed. Look at
> the new summary and confirm again.

and a fresh review block replaces the stale one.

### When nothing can be configured yet

If every detected destination came from the project's own files, there is nothing
Tethra may configure on its own. The page says so and offers no confirmation:

> There is nothing Tethra can configure automatically for this folder yet.
> Approve a destination above, then select the folder again.

with the destinations listed and the note that approving them happens in advanced
tracking diagnostics, where the full disclosure for that decision is shown.

## Tracking states

| State | Wording |
|---|---|
| No folder | the Select project folder call to action |
| Linked, awaiting setup | `waiting for setup` |
| Linked and working | `on` |
| Linked, not working now | `needs attention` |
| Disabled | `off` |
| Attribution paused | "Requests are still being recorded, but credential attribution is paused until the vault is unlocked for it." |

Tracking state is always the present tense, resolved by the one health resolver.
A setup that worked earlier and is not working now reads `needs attention`.

## Live activity

* Refreshes when the page opens, then about every 5 seconds while visible.
* Slows to 60 seconds while the window is hidden.
* Refreshes at once when the window regains focus.
* A visible **Refresh** button, and `Last updated 8 seconds ago`.
* A failed refresh shows the error and **keeps the last good figures**, adding
  "The figures below are from the last successful refresh."
* Repeated failures back off to at most 60 seconds and recover on success.

With no traffic yet:

> Waiting for the first request. Tethra is watching this project; run it and
> activity appears here automatically.

Not zeroes.

## Cost

Complete:

> Every request in this period was priced from local pricing records. 100% of
> token usage priced.

Partial:

> **Cost is partial for this period.** 76% of token usage priced.
> Unpriced usage: 3 request(s) / 12,400 tokens.

Requests that reported no usage at all:

> 4 request(s) reported no token usage, so their tokens are unknown — not zero.

An unpriced total is never rendered as a dollar amount. **Review model pricing**
expands a table naming each provider/model that could not be priced and why.

## Unknown APIs

An API not in the catalog stays visible with everything that is actually
recorded:

> Unknown API — api.example.com — 12 requests — 0 errors — 420 ms —
> Cost estimation unavailable

and:

> An API Tethra does not recognise still reports requests, status, endpoint and
> latency. Credential attribution and cost estimation are unavailable for it, and
> naming it here does not change where any traffic goes.

**Name it** gives the host a display name. That is all it does.

## Credentials

Detected variables appear with:

```text
Detected variable: ANTHROPIC_API_KEY
Suggested provider: anthropic
Suggested name: anthropic-api-key
Environment: unknown
Source: .env
Value status: Not saved in Tethra
Attribution status: Pending exact key
```

The summary says explicitly that they do not block anything:

> 2 credential(s) need details. Tracking is already running — completing them
> only adds per-credential attribution.

Per row: **Ignore** or **Managed elsewhere**. To store a value, add the
credential to the project through the normal credential form — the same secure
path every other credential uses. Tethra never saved a value for a detection.

## Lifecycle

**Disable tracking** — stops future automatic configuration. Folder linkage,
credentials, detections and every recorded observation stay. Re-enabling is one
click. Managed file changes are not touched; restoring them is a separate action.

**Unlink folder** — confirmation lists: the association is forgotten; the project,
its credentials and its recorded activity are kept; the folder and its files on
disk are not touched; configuration written into `.env` files stays until undone
from advanced tracking diagnostics.

**Delete project** — unchanged from before, and now also cascades the folder
linkage and the detections. The user's source folder is never touched.

**Re-selecting the same folder** changes nothing and preserves the scan state.
**Choosing a different folder** clears the previous folder's scan state, because
a fingerprint and an applied generation describe the old folder. Neither
re-enables tracking the user turned off.

## Relaunch

On launch Tethra reads the linkage rows and resolves health once against a single
liveness probe. It does not rescan any folder, does not re-apply any
configuration, and writes to no project file. A folder whose manifests changed
while the app was closed shows:

> This project's dependency or environment files changed since the last scan.
> Rescanning updates what Tethra knows; it does not change your files.

Offering a rescan is not performing one.

## Navigation

**Projects** is the primary entry. The former **Track API activity** item is
**Tracking setup (advanced)** under Advanced. It is not removed: destination
approvals, per-step diagnostics and undo are still only reachable there.
