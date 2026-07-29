# Troubleshooting tracking

Start with the built-in diagnosis. It checks **most** of the causes below in
order and tells you which ones actually apply to your project. Two of them —
"you pointed Tethra at the wrong folder" and "a proxy is bypassing the
gateway" — have **no automated check** and are marked *(manual)* where they
appear; the diagnosis will not mention them, so read past its output if it
comes back clean. (This page previously implied all eight were automated —
audit finding `ZFT-VAL-15`.)

* Desktop: the project's card on the Activity dashboard → **Run tracking
  check**, or **Run diagnostics** on the waiting screen.
* Terminal: `tethra track doctor`

## "Waiting for traffic…" never becomes "Tracking verified"

Tethra only claims verification after a real request from your project is
recorded, so this state means exactly what it says: nothing has arrived
yet. In rough order of likelihood:

**1. The project wasn't restarted.** A running process keeps the
environment it started with. Restart it, then make one request. This is
the single most common cause.

**2. The app doesn't load `.env`.** Tethra reports "no dotenv loader was
detected" when it read your manifests and found none. If your app doesn't
read `.env` files, set the variable in whatever actually starts the
process (your shell profile, your process manager, your container spec).
The variable name is in the diff Tethra showed you — typically
`OPENAI_BASE_URL` or `ANTHROPIC_BASE_URL`.

**3. The variable is overridden somewhere else.** Tethra flags this when
the same variable is also set in a later-loaded file (`.env.local`,
`.env.production`, …). The later value usually wins. Remove it there, or
point it at the same local URL.

**4. The project runs in Docker or Compose.** A container doesn't see
your machine's `.env` change, and `127.0.0.1` inside a container is the
container itself, not your machine. Tethra detects a compose file and
says so. Tracking a containerized project is not supported yet.

**5. The project runs on a remote machine or in a devcontainer.** Same
reason. Tethra flags a `.devcontainer` directory as a possible cause.

**6. The SDK ignores the base-URL variable.** Some SDKs only accept a
base URL in code, not from the environment. If your client constructs its
own base URL, pass the local one there instead.

**7. Wrong folder** *(manual — no automated check).* If you picked a parent or sibling directory, the
`.env` Tethra edited isn't the one your app reads. Check the file path in
the diff against the one your app loads.

**8. Traffic is bypassing Tethra** *(manual — no automated check).* If a proxy variable is set
(`HTTP_PROXY`/`HTTPS_PROXY`), loopback traffic can detour around the
local service. Tethra adds `NO_PROXY` entries for loopback during setup;
if you removed them, restore them.

## "Tracking is partially configured"

A step failed and Tethra stopped rather than continuing blindly. The
report names the step, what was changed, and what wasn't. Completed steps
are left in place — nothing is silently rolled back.

* **The service could not be installed** — on unsigned builds macOS may
  refuse to run the background helper. Use **Track while the app is
  open** (foreground mode; tracking pauses when Tethra closes), or allow
  it in System Settings → Privacy & Security and try again.
* **"The environment files changed since the preview"** — a file was
  edited between the preview and applying. This is the safety check
  working: a stale plan is never written. Re-run setup to see the current
  diff.
* **A route failed** — the report names which one. Others still applied.

`tethra track undo` (or **Stop tracking…**) restores everything from a
partial state.

## "Credential attribution paused"

Traffic is still being recorded — only the credential labeling stopped.
It happens when the vault locks, when the key's window expires, or when
the key was revoked. Click **Resume attribution** and enter your master
password. On Windows, attribution is structurally unavailable.

## Some APIs show traffic and others don't

That is `partially_observed`, and it is usually correct: an API your app
hasn't called yet has nothing to observe. Tethra keeps watching. If an
API you *are* calling shows nothing, run the diagnosis for that project.

## "No trackable APIs detected in this folder"

Tethra read the folder's `.env` files, package manifests, and lockfiles
(6 levels deep, nothing executed) and found no API it can configure. Most
often:

* The provider isn't supported yet (Stripe and GitHub are detected but
  their SDKs don't read a base-URL environment variable).
* The folder isn't the project root — the manifests are elsewhere.
* Keys are placeholders (`your-key-here`), which don't count as evidence.

The Advanced → Gateway internals screens still let you configure a route
by hand.

## "Refusing to scan …"

Tethra refuses to scan the filesystem root, your home directory, or the
directory containing everyone's home directories. Pick the project folder
itself.

## The helper is missing

"The helper that runs tracking could not be found or executed" means the
binary that ships inside the app couldn't be located or refused to run.
Reinstalling Tethra restores it. Advanced users can also put a `tethra`
CLI on `PATH`.

## Expert diagnostics

Everything above is also visible in the low-level surfaces:

```bash
tethra gateway doctor     # service, listener identity, routes, links
tethra gateway status     # live counters and recording state
tethra track status       # the tracking state machine and freshness
```

In the desktop app these live under **Advanced → Gateway internals**.
