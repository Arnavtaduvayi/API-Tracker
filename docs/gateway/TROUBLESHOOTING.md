# Local Gateway — Troubleshooting

Start with:

```
tethra gateway doctor
```

Doctor runs the same diagnosis engine the desktop Diagnostics tab renders:
every finding below carries a stable id, a severity, and a repair action
where one exists. Doctor never needs the vault password.

## Doctor findings, by id

### `not_installed` (info)
No service is installed and nothing is running for this data directory.
Fix: `tethra gateway install`, or run in the foreground with
`tethra gateway serve`.

### `installed_but_stopped` (warn)
The service exists but no gateway is serving. Linked projects get
connection-refused until it starts. Fix: `tethra gateway start`; if start
fails, read `<data-dir>/logs/gateway.log` and run `tethra gateway repair`.

### `running_manually` (info)
A gateway is serving but no login service is installed — it dies with your
terminal. Fix (optional): `tethra gateway install`.

### `port_collision` (error)
Something is listening on the persisted gateway port **and it failed the
identity probe** — it could not prove knowledge of this data directory's
per-boot nonce, so it is not this vault's gateway (a foreign process, or
another vault's gateway). Linked projects would send API traffic to
whatever owns that port. Fix: `tethra gateway restart`; if the squatter
persists, find and stop the other process, then `tethra gateway repair`.

The identity probe is why Tethra never trusts a bare open port or a PID:
the listener must answer a challenge derived from the 0600 nonce file
before status calls it healthy or a `.env` write proceeds.

### `control_auth_failed` (error)
A gateway is listening but refused this session's control nonce — usually a
stale `gateway.nonce` file after a crash, or two gateways fighting over one
data directory. Status and graceful stop are unavailable until fixed. Fix:
`tethra gateway restart`.

### `control_nonce_missing` (warn)
A gateway is listening but the nonce file is gone (crash cleanup). Same
consequences and fix as above.

### `version_mismatch` (warn)
The running service is a different version than this CLI. Behavior can
differ until they match. Fix: `tethra gateway repair` (re-copies this
binary and restarts).

### `recorded_version_drift` (info)
The installed binary's version differs from the recorded one. Fix:
`tethra gateway repair`.

### `invalid_route_snapshot` (error)
Route rows exist that cannot be loaded (unknown provider, invalid origin,
tampered prefix). Requests to them answer 404. Fix: remove and re-add the
affected route (`tethra gateway route remove <prefix>` then `route add`).

### `routes_disabled` (info)
Disabled routes answer 404 exactly like removed ones; only this count tells
the difference. Fix if unintended: `tethra gateway route enable <prefix>`.

### `route_reads_degraded` (warn)
The running gateway cannot re-read route configuration (database missing,
busy, or at a different schema version). Forwarding continues on the
last-known-good table; recent route changes are not live. This clears
itself when the database is readable again.

### `recording_paused` (warn)
Forwarding continues but nothing is recorded — this window is a permanent
coverage gap. Fix: `tethra gateway recording resume`.

### `recording_degraded` (warn)
Observation persistence is failing (persist failures are counted);
forwarding is unaffected. Usual causes: database locked by a long
operation, disk full, schema from a different build. The writer retries;
the count tells you how much history was at risk.

### `buffering` (info)
Events are queued ahead of the writer. Normal under load; watch
`buffer_overflow` instead.

### `buffer_overflow` (warn)
The observation queue overflowed and events were dropped to protect
forwarding. Those exchanges are a permanent coverage gap (the drop count is
itself recorded). If chronic, the database is too slow for the traffic —
check disk and concurrent load.

### `coverage_gap` (warn)
An umbrella finding: dropped, paused, or unpersisted windows exist, so the
local record understates real traffic. Never read gateway history as
complete while this is present.

### `vault_locked_attribution` (info)
No matching key is resident: exchanges record `unavailable_no_key`
instead of a credential match. Forwarding and metadata recording are
unaffected. Fix (optional): `tethra gateway push-key`.

### `unhealthy_process` (error)
The listener answers its identity probe but the control channel gives no
status — the process is degraded. Fix: `tethra gateway restart`.

### `stale_service_path` (error)
The installed service definition points at a **different data directory** —
that login slot belongs to another vault, and this vault's gateway will not
start at login. Fix: `tethra gateway install --force` (replaces it), or
uninstall the other vault's service first.

### `service_binary_missing` (error)
The service definition points at a binary that no longer exists (moved,
cleaned, or a partial upgrade). Fix: `tethra gateway repair`.

### `linger_off` (info, Linux)
systemd user services stop at logout unless lingering is enabled. Tethra
reports this and never changes it. If you want the gateway to outlive your
session: `loginctl enable-linger` (your call).

### `windows_never_validated` (warn, Windows)
The registration exists, but Tethra's Windows service lifecycle is
compile-validated only — it has never been executed on a real Windows
machine. Treat foreground `tethra gateway serve` as the supported mode.

### `linked_projects_at_risk` (warn)
One or more linked projects need attention. Per-link issues include: the
linked `.env` file is missing; the file no longer carries the link's
gateway URL (edited or restored by hand); the URL points at a different
port than the persisted one (the gateway moved — re-link); `NO_PROXY` is
gone; or the file points at a gateway that is disabled and not running.
Each issue names its own fix; `tethra gateway link` re-applies, and
`tethra gateway unlink` restores.

### `database_unavailable` (warn)
The vault database is missing, busy, or at a different schema version.
Configuration and history reads degrade; a running gateway keeps
forwarding.

### `service_query_failed` (warn)
The platform service state could not be determined (e.g. `HOME` unset, or
`systemctl`/`launchctl` unavailable). The rest of the diagnosis still runs.

## Symptoms not tied to one finding

### A linked SDK gets connection-refused on 127.0.0.1
The gateway is stopped, disabled, or moved ports. `tethra gateway status`
shows which; `start` fixes the first two. If the port drifted (status shows
a different persisted port than the `.env` carries), re-run
`tethra gateway link` for the project — doctor reports this as a
`linked_projects_at_risk` issue.

### Traffic flows but the gateway records nothing for a project
The client is not actually using the base URL:

- the SDK does not read `.env` at all (no dotenv loader in the project —
  the link warns about this heuristically). Export the variable in the
  shell or load the file explicitly.
- the base URL is hardcoded in code, overriding the environment.
- the process started before the link and still has the old environment.
  Restart it.
- a docker-compose service has its own environment and never reads the
  linked file (the link warns when a compose file is present).

Absence of recorded traffic is never evidence of absence of traffic.

### HTTP_PROXY / corporate proxy interplay
If `HTTP_PROXY`/`HTTPS_PROXY` is set and `NO_PROXY` does not cover
`127.0.0.1`, some clients send loopback requests to the proxy — in
cleartext. The link writes/extends `NO_PROXY=127.0.0.1,localhost,::1` for
exactly this reason and warns when a proxy variable is present. If you
removed the `NO_PROXY` entry, doctor flags the link.

### The `.env` is shared (committed, or used by teammates)
Linking a git-tracked file is warned about before writing: the loopback URL
(with its 128-bit link slug) would be committed and useless (or misleading)
on other machines. Prefer an untracked `.env`, and keep gateway wiring out
of `.env.example` (Tethra's example generation skips marked lines
automatically).

### Control channel unavailable, long data-directory path
Unix sockets cap the path at ~104 bytes. A very long `TETHRA_DIR` makes the
control socket unavailable: no status, no attribution, no graceful stop —
forwarding and recording continue, and `serve` prints exactly what is lost.
Fix: use a shorter data directory path.

### Stale runtime files after a crash
`gateway.sock`, `gateway.nonce`, and `gateway.pid` can survive a crash.
Liveness is decided by connecting to the socket (never by trusting a pid),
a fresh start replaces stale files, and `tethra gateway restart` clears the
usual confusions (`control_auth_failed`, `control_nonce_missing`).

### Uninstall reported problems
Uninstall reports every path it removed and every restore outcome. If a
`.env` restore failed, the link row is kept — fix the reported problem
(permissions, missing directory) and run `tethra gateway unlink` for that
project, then `tethra gateway uninstall` again. `tethra gateway status`
lists every artifact the feature owns, so "is anything left?" is a
checkable question.

### macOS: install fails with an execution-probe error
On unsigned alpha builds Gatekeeper may kill the copied binary. The install
probes execution *before* registering anything, so the failure is honest
and nothing is left behind. Options: allow the binary in System Settings →
Privacy & Security and re-run `tethra gateway install`, or use foreground
mode (`tethra gateway serve`), which runs the binary you already launched.
