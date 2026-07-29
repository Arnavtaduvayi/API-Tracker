# Tracking your API activity

Tethra can watch a project's API traffic on your own machine and show you
requests, errors, latency, tokens, models, and an estimated cost — as
metadata only. It never records your API keys, authorization headers,
cookies, query values, prompts, request bodies, or response bodies.

## The desktop flow (no terminal required)

1. **Open Tethra.** The app opens on **Activity**, its home screen.
2. **Add a credential** for the API you use (Vault → Projects →
   Credentials). This is optional for tracking itself, but it is what
   lets Tethra label observed requests with the credential that made
   them.
3. **Click "Track API activity."**
4. **Select your project folder** in the native picker. Tethra reads only
   that folder — bounded depth, bounded file sizes, nothing executed,
   nothing uploaded.
5. **Review what it found.** One screen shows:
   * every detected API with its confidence and the plain-language
     evidence ("Found OPENAI_API_KEY in .env (value not read)");
   * the exact changes to your environment files, as a diff;
   * what starting tracking will do, and what is never recorded;
   * an optional master-password field that turns on credential
     attribution in the same step.
   Deselect anything you don't want. APIs Tethra cannot observe yet are
   listed honestly and never block the ones it can.
6. **Click "Start tracking."** Tethra installs its local service, creates
   the provider routes, applies the file changes, checks the path to each
   provider, and turns on attribution — in one sequence, with a per-step
   report.
7. **Restart your project** if Tethra says to (a running process keeps
   its old configuration).
8. **Make one API request** from your app.
9. **See it verified.** Tethra says "Tracking verified" only when a real
   request from your project has been recorded **and** everything that
   request depended on is still working right now: the local service is
   answering and proves it is yours, the route and the project link still
   exist, and no later failure supersedes the observation. Until then it
   tells you exactly what it is waiting for.

That is the whole flow: no route forms, no linking step, no separate
attribution setup, and no terminal commands.

## The one-command terminal flow

If you prefer the terminal, the equivalent is one command:

```bash
tethra track .
```

It resolves (or creates) the project for the folder, scans, prints the
combined plan and diff, asks once, applies, then waits for and verifies
the first real request.

```bash
tethra track .                     # set up and verify the current folder
tethra track . --project my-app    # attach to a specific Tethra project
tethra track . --dry-run           # show the plan and diff, change nothing
tethra track status                # current state and per-API freshness
tethra track doctor                # ranked diagnosis when nothing arrives
tethra track undo                  # restore the files, remove what track made
```

Exit codes: `0` configured and verified, `2` configured but not yet
verified (no traffic seen in the waiting window — tracking stays on),
`1` error.

`track` asks for your master password itself when it needs one. It never
prints shell-export instructions. With `--yes` it runs non-interactively
and includes attribution only if `TETHRA_PASSWORD` is set, otherwise it
skips attribution and says so.

## What "verified" means

Configuration is not the same as coverage, so Tethra separates them:

* **Configured** — routes exist, your environment files point at the
  local service, and a keyless path check reached the provider.
* **Verified** — a real request from your project actually reached Tethra
  and was recorded.

Only the second one is reported as "Tracking verified." A state that
claims traffic is re-derived from the recorded observations every time it
is read, so a stale record cannot claim coverage it doesn't have.

**"Verified previously" is a different answer, and it is not a success.**
If traffic was observed and then the service stopped, or the route or link
was removed, the desktop and `tethra track status` both say so under a
present-tense heading, with the historical fact shown beside it rather than
instead of it. `tethra track` and `tethra track status` **exit non-zero** in
that case, so a script that gates on tracking working is never told yes while
your requests are failing (`ZFT-005`, `NEW-01`).

## Credential attribution

Attribution labels each observed request with the stored credential that
made it. It is part of turning on tracking, not a separate feature: the
Start-tracking screen has one master-password field for it.

Attribution can pause on its own — when the vault locks, for example.
When it does, the dashboard says:

> Credential attribution paused — traffic is still recorded.

Traffic keeps flowing and keeps being recorded; only the credential
labeling stops. **Resume attribution** on the dashboard turns it back on.

## Stopping

Dashboard → the project's card → **Stop tracking…** (or `tethra track
undo`). Tethra restores your environment files to their recorded
pre-tracking state, reports anything you edited yourself instead of
overwriting it, removes the routes it created unless another project
still uses them, and keeps all recorded history — that's your data.

## Honest limits

* Only traffic whose base URL points at Tethra is observed. Traffic that
  bypasses it is not seen, and an empty view is never proof of zero
  usage.
* Locally observed traffic is never summed with provider-reported usage;
  the two appear in separate, labeled places.
* Cost is an estimate and a lower bound (cache-read tokens are excluded).
* Some APIs are detected but not yet observable this way, because their
  SDKs don't read a base-URL environment variable. Tethra lists them and
  says why.
* Projects that run in Docker or on a remote machine won't see your
  machine's `.env` change or its `127.0.0.1`. Tethra diagnoses this
  rather than pretending it works.
* On Windows, the supported mode is foreground tracking, and credential
  attribution is unavailable.

See `TROUBLESHOOTING.md` when traffic doesn't appear, and
`KNOWN_LIMITATIONS.md` for the full list.
