# Tethra Mesh — Known Limitations

What the mesh does not do, stated plainly
([ADR 0031](../decisions/0031-device-mesh.md)). Each entry says whether it is a
permanent design choice or something a later increment changes.

> **Status.** All twelve increments are built: pairing, the node, shared
> projects and cross-device usage, spend caps with gateway enforcement, the
> desktop app's Devices view and project panels, opt-in credential sharing,
> and hardening with an independent audit (2026-11-03; 41 findings fixed, 7
> accepted). These limitations describe what is built; the ones the audit
> accepted rather than fixed are marked "(accepted, audit 2026-11-03)".

## Reachability

- **No NAT traversal, relay or rendezvous.** Devices must reach each other
  directly: the same LAN, or a VPN you run (Tailscale, WireGuard). There is no
  Tethra server to fall back on, by design.
- **Nothing listens unless you ask.** `tethra mesh serve` requires `--listen`;
  all-interfaces binding requires `--all-interfaces`; LAN discovery requires
  `--discover`.

## Membership

- **Removal is eventually consistent.** A removed device keeps exchanging with
  devices that have not yet heard of its removal. Each device refuses it at its
  next handshake after hearing.
- **Leaving without a reachable peer.** `mesh leave` wipes this device either
  way. If no peer was reachable to receive the departure, the other devices
  keep listing it until one of them removes it. The same holds when this
  device's identity is untrusted (its marker missing, mismatched, rolled back
  or unreadable) or held by a rollback notice: it then announces nothing, and
  only wipes (audit MI-2).
- **The invite is a bearer secret.** Anyone who has it during its lifetime can
  add a device. On the command line it ends up in shell history; pass `-` to
  read it from standard input instead.
- **The shown invite passes through ordinary strings** (accepted, audit
  2026-11-03, MD-15). To reach you once, the invite is formatted and returned
  (CLI output, the desktop dialog) in plain, non-zeroized strings, which can
  stay in freed memory. It is single use and expires (10 minutes by default,
  at most 60), which bounds what a later memory read gains.
- **Pairing reveals the inviter's static key to a client that knows a live
  invite's hint** (message 2 of `XXpsk3` comes before the psk is mixed in). The
  hint is derived from the token, so in practice that means someone who saw
  the invite.
- **Access-key rotation is eventually consistent.** Every session carries the
  current access key, so a rotation spreads as devices talk. A device keeps
  being accepted with the previous key for 30 days after the rotation; after
  that it must pair again. If two devices remove different devices while apart,
  a removed device can briefly get a current key from a member that has not
  yet heard of its removal. Members that have heard still refuse it, because
  the roster check, not the key, decides who gets in.
- **A compromised member is powerful.** It is your own device: it can remove all
  your other devices (recovery is re-pairing), publish false usage about itself,
  and raise its own spend cap with a labelled override. Item signatures stop it
  impersonating another device, key-derived device ids stop it taking
  over another device's identity, and the spend-cap clamp stops it creating
  rights in other devices' views beyond what it held.
- **A compromised member can pin a replicated setting** (accepted, audit
  2026-11-03, MP-6). Last-writer-wins values (a cap's target, a shared
  project's name, archived flag and merge, the retention setting) are ordered
  by their hybrid-clock timestamp, then the writing device. A member that writes one at a far-future timestamp, up to
  the clock's maximum, wins against every later honest write. A fixed
  timestamp ceiling would only move where such a write pins the value; the
  real fix is for each write to name the entry it replaces, a payload change
  for every such kind, and is not built. Recovery: remove the device and
  replace the pinned object (a new cap, a new shared project, or, for a mesh
  setting, a new mesh).
- **The access key does not withstand a member** (accepted, audit 2026-11-03,
  MP-8). Two rotations to the same epoch converge on the key with the larger
  hash, which a device can choose (grind) for its own rotation, and the epoch
  ceiling counts removals, including removals of device ids a member made
  up. The access key is defense in depth only: the roster check after the
  handshake is what refuses a removed device.
- **Mutual removal removes both.** If two devices remove each other at the same
  time, both are removed.
- **Concurrent removals keep the smaller cutoff.** When two devices remove the
  same device having seen different amounts of its history, the removed
  device's items count only up to the lower of the two cutoffs (audit MP-1:
  the larger one let a removed device cancel its own removal).
- **A fork report rests on the reporting member's word.** Any known device's
  `fork.report` counts, and the hashes in it are not signed items: a
  compromised member can report any device forked, directly or by feeding an
  honest device false chain hashes. A device never reports itself forked from
  a peer's claim (audit MP-2), and a falsely reported device recovers like a
  forked one (leave and pair again, after removing the member that lied).
- **A join that cannot verify its inviter keeps nothing.** If the first
  exchange does not deliver an inviter roster entry with the Noise key that
  answered the pairing (a dropped connection, or a mismatch), `mesh join`
  fails and wipes the new identity (audit MP-12). The inviter has already
  added the device, so its list shows a device that never connects: remove it
  there (`tethra mesh remove`) and pair again with a new invite.
- **Only a device's latest value per key is kept.** When a removed device's
  latest write to a value came after its removal cutoff, that value stops
  counting, and its *earlier* value is not restored: the value falls back to the
  next device's.

## Transport

- **Key copies inside `snow`.** Tethra's own copies of private keys and psks are
  zeroized when dropped, but the Noise library (`snow` 0.10) keeps its own
  copies in its handshake and cipher states and does not zeroize them.
- **Handshake budget.** A client may hold one of a listener's 8 connection
  slots for up to the 5-second handshake timeout, and may make 10 attempts a
  minute from one address. Many addresses can deny service for as long as they
  keep it up.

## Identity and storage

- **A restored backup leaves the mesh.** Backups carry no mesh rows (identity,
  keys, items, peers, invites), only the device id the vault had, because a
  restored vault is a copy: if it kept minting as the original device, the two
  would reuse item numbers. Pair the restored device again. A backup made by
  an older build still holds those rows inside its encryption; restore skips
  them.
- **The identity marker sees large rollbacks, not small ones.** The marker
  reserves item numbers in blocks of 64 and records the log length committed
  when it was written, so a database rolled back by less than about one block
  (or past one large batch whose follow-up marker write failed), or a copy of
  the whole data directory (database and marker together), is not caught
  locally. It is caught as a fork when the diverging histories meet another
  device, and the copy's later items stop counting.
- **A power loss can look like a rollback.** Every write is synced
  (`synchronous=FULL`, and F_FULLFSYNC on macOS). But if a disk still loses more
  than 64 of this device's most recent writes while the marker survives, the
  device refuses to mint until it leaves and pairs again. That is the safe side
  of the error.
- **Fork evidence can be reported one exchange late** (accepted, audit
  2026-11-03, MI-7). A large exchange commits in several chunks; if a chunk
  after the one that noted a fork fails, the fork is not reported from that
  exchange. The evidence is found again at the next exchange's chain
  comparison.
- **One device's batch is one transaction.** A large exchange is written in
  several short transactions, but everything received from one origin in one
  exchange is a single transaction (at most the 50 000-row session limit), so
  the gateway's writer may wait for it. Measured on a Mac: 10 000 items in about
  60 ms, so the 50 000-row maximum takes roughly 0.3 s.
- **Windows: marker permissions and directory sync.** On Unix the marker is
  0600 in a 0700 `mesh/` directory, and its directory is fsynced after every
  rename. On Windows the file inherits the data directory's per-user ACLs (as
  the vault's files do), and the directory is not fsynced (the standard library
  cannot open a directory there; NTFS journals the rename).
- **Downgrading after the audit release leaves the identity untrusted.**
  The identity marker is now version 2 (it records the committed log length).
  A build from before it reads version 2 as unknown, so the device refuses to
  mint until it leaves and pairs again.
- **A repair larger than one session never completes.** Repair items fit in
  what a session may stage (50 000) after the main path; a cut-short repair is
  sent again from its start, so an origin holding more items than that is
  never repaired in full. Honest operation needs repair only after forks or
  rare divergences.
- **Opened views cost memory and start-up time.** The views are rebuilt in
  memory from the stored items whenever the store opens (`mesh status`, and the
  node from 05). This is linear in the number of held items: one per device, key
  and day for usage, so it grows with history.

## Running the node

- **No background service for the mesh in v1.** There is no LaunchAgent,
  systemd unit or Windows service: the node runs only while `tethra mesh serve`
  runs, or while the desktop app is open and unlocked with "Run mesh while
  Tethra is open" on. A
  service would have to hold keys while the vault is locked, which ADR 0020
  forbids. A device whose node is not running replicates only when someone runs
  `tethra mesh replicate`.
- **A node started from a vault session stops when the session does.** The
  session's auto-lock counts time without `tethra` commands, and the node does
  not reset it (MESH-SI-7), so such a node runs at most the auto-lock period
  after the last command. Scripts use `TETHRA_PASSWORD` with an optional
  `--max-runtime`.
- **Ctrl-C ends the node abruptly.** Like `tethra gateway serve`, `mesh serve`
  installs no signal handler: the process exits at once, without the explicit
  key-drop sequence (the operating system reclaims its memory). Stored state is
  safe: every write is one transaction and an interrupted exchange commits
  nothing. `tethra mesh stop` is the graceful stop.
- **Stopping waits for running exchanges.** After a stop request the node
  starts nothing new, but an exchange in progress finishes first, bounded by the
  30 s idle and 10 min session limits.
- **Windows runtime is untested by hand.** The node, its loopback-TCP control
  channel and discovery compile on Windows, and Windows CI runs the node's
  automated tests (real sockets on 127.0.0.1, the control channel, one node per
  data directory, stopping on session end) and they pass. Nobody has run a node
  on Windows by hand, as for the gateway (ADR 0019 D8). Its
  single-instance check (a live node answering on the port recorded in the nonce
  file) is weaker than the Unix socket lock: two nodes started in the same
  instant could both start.
- **Two nodes started at the same instant on a stale socket** (accepted, audit
  2026-11-03, MI-6). On Unix the single-instance check replaces a control
  socket nobody answers on; two nodes started in the same instant against a
  stale socket can both get past it. The database stays consistent (one writer
  per transaction, and a node reloads its views when another process has
  committed); stop one of them with `tethra mesh stop`.
- **Data directory paths are limited** to about 100 bytes on Unix, because the
  control socket lives inside it (`<data-dir>/mesh/node.sock`), as for the
  gateway's socket. A longer `TETHRA_DIR` makes `serve` fail with a clear error.
- **No peer-credential check on the control socket.** As for the gateway, the
  0600 socket in a 0700 directory and the 0600 nonce keep other local users out;
  a process running as the same user can drive the node (status, replicate now,
  stop), which is inside the local trust model. It cannot read keys through it.
- **mDNS is link-local and best effort.** `--discover` finds devices on the same
  LAN segment only: not across routers, VPNs or networks that filter multicast.
  It was not exercised on a real network in the session that built it (CI never
  multicasts; tests use an in-memory fake). Announcements are unauthenticated:
  anyone on the LAN can announce a fake address carrying a stale or random tag;
  that costs a dial, never admission (the handshake checks the roster).
- **Gossiped addresses are dialled as published.** A member can publish any
  address (at most 16), and other nodes will dial it with backoff. A malicious
  member could point them at a host on their network; the dial sends only the
  16-byte preamble and the first handshake message.
- **A member can delay this device's writes with false rollback reports.** A
  `RollbackNotice` makes this device hold every mint until it has its own items
  back up to the reported seq (PROTOCOL.md §7.4). A member that reports items it
  never sends holds this device's writes for the duration of each exchange with
  it, and, if it keeps reporting, until it is removed (`mesh remove` lifts its
  report).
- **Lag is measured at the last exchange**, not continuously: a device not heard
  from shows its last figures with their time.
- **The desktop's node stops with the app, not instantly.** On a lock the app
  signals its node and returns; the node finishes the exchange it is in
  (bounded by the session limits) before its threads end and its keys are
  dropped. On quit the app waits up to 5 s for that, then exits; the operating
  system reclaims the rest. A crash or a killed process skips the sequence, as
  for the gateway. While a stopped node is still finishing, turning the node on
  again waits up to 10 s and otherwise says so.
- **The desktop's node and `tethra mesh serve` exclude each other.** One node
  per data directory: whichever starts first holds it, and the other reports
  why it could not start. The desktop shows a CLI node and replicates through
  it, but cannot change its settings.
- **Listen addresses in the desktop are IP literals.** The app listens on
  `IP:PORT` addresses only (no host names, no `--advertise` equivalent): the
  node publishes the addresses it is bound to. A device reachable under a VPN
  name can be dialled by name from the others (`peer add`), or run
  `tethra mesh serve --advertise`.

## Usage and cost

- **Cost is computed where the usage happened.** Each device prices its own
  traffic with its own pricing table at ingest time; figures from different
  devices may use different price versions, and a price added later is not
  applied to usage already published.
- **Cached-read tokens are excluded from cost estimates**, so the estimate (and
  later the spend caps) undercount cached-heavy traffic.
- **Gateway-observed only.** Only traffic that went through a device's
  gateway, for a project bound on that device, is counted.
- **The split is unknown before the upgrade.** Traffic a device recorded
  before migration v23 cannot be told apart as priced or unpriced: it shows as
  "split unknown" (its not-extracted part is known). A daily row that already
  existed at the upgrade stays "split unknown" for that day.
- **Figures are per device, with freshness.** "As of" is the last direct
  exchange with that device; figures relayed through another device can be
  newer than it says. A device not heard from in over 24 hours is shown as
  stale, never as zero; mesh figures are never summed with provider-reported
  cost.
- **Who has bound a project is private to each device.** The mesh sees only
  who has published usage for it, so "no data from X" covers both "X has not
  bound it" and "X has not been heard from".
- **Deletions reach other devices when they exchange.** A deletion is
  published as lower totals with a higher epoch; a device that is off keeps the
  old figures until it next exchanges.
- **Retention drops data on every device.** After `retention.usage_days` plus
  two days, counters are dropped everywhere; there is no per-device override.
  Lowering it in the CLI asks first (`--yes` for scripts); a dropped counter
  cannot be brought back. The desktop app has no retention control.

## Spend caps

- **After a lower, the owner gives up its own unspent share first when other
  devices spent past theirs.** A decrease must bring the rights in existence
  down to the new cap (or to what was already spent); devices that overspent
  have nothing left to burn, so the cap's owner burns from its own share the
  part they cannot cover (ADR 0032 D12). The owner can then spend less this
  month than an equal share would suggest.
- **Enforcement is per device and opt-in.** A device's gateway refuses requests
  over a cap only after `tethra mesh cap enforce` there; elsewhere the cap
  raises alerts and a device can spend past its rights (its available amount
  then shows below zero).
- **Caps are a self-limit, not a security boundary.** Anything that bypasses
  the gateway bypasses the cap. The figure is the gateway's estimate (priced
  requests only, cached-read tokens excluded), priced on each device with its
  own pricing table.
- **Overshoot is limited, not zero, and not "one request".** Cost is known
  only after a response. Near the cap, and while no request cost is known
  (a new cap, or one with no priced request in this gateway's history yet), requests run one at a
  time, so a device goes over by that request's cost. Otherwise see the next
  entries: concurrent requests far above the typical cost, and spend a
  restart forgets, can take it further.
- **A device's own overrides survive a lower.** A lower never burns, and
  the owner never reclaims, rights a device holds under its own overrides
  (audit MC-6). If other devices overspent while apart, the month's total
  can therefore end above the effective target by up to what overrides still
  hold, spent by the device that raised its own limit.
- **A removed device's later cap figures stop counting.** After a removal,
  its `cap.used` written above its cutoff no longer counts and its earlier
  figure is not restored, so the cap's total spend can drop by what it
  reported after the cutoff (with concurrent removals, the smaller cutoff
  applies).
- **Unpriced or unmetered traffic is never charged.** A model with no pricing
  record, or a response that reported no usage (an OpenAI stream without
  `stream_options.include_usage`, a route without usage extraction), is
  admitted and counted as unpriced or unmetered, not against the cap; `cap
  show` and `gateway status` show the counts. It is still subject to the
  one-at-a-time rule: while no request cost is known for the cap, which stays
  true if all its traffic so far is unpriced, a second request in flight gets
  the serialized 403.
- **Concurrency is bounded by the typical request.** Beside other in-flight
  requests, a request is admitted only while every in-flight request's
  reserved cost (the cap's recent 95th-percentile) still leaves the margin;
  several requests that each cost far more than that can together go over by
  more than one request.
- **The gate fails open.** No mesh, a database the gateway cannot open or that
  is newer than it, or a poller stuck for a minute: the gateway forwards
  everything and reports why.
- **A refused request can hold a connection for up to 5 s** (accepted, audit
  2026-11-03, MC-11). After the 403 the gateway reads and discards the unread
  request body (at most 5 s and 64 MiB) so the client sees the refusal rather
  than a reset; a client sending refused requests can keep connection threads
  busy that long each.
- **A transfer can be decided against a gateway that is just starting**
  (accepted, audit 2026-11-03, MC-9). The node checks whether the gateway runs
  before its write transaction, not inside it. A gateway that starts in
  between can, until its next refresh (5 s), admit spend against rights the
  node has just given away without its acknowledgement.
- **A restart can forget recent spend.** Spend the writer had not persisted
  (records dropped under load, or recording paused) is counted in memory only;
  after a gateway restart it is gone. `gateway status` flags it as accounting
  incomplete.
- **A transfer can slip past spend not yet persisted.** The node reserves
  rights it gives away against the spend the gateway's writer has persisted;
  it re-checks at publication, but spend persisted after that (writer lag of
  seconds) is not covered.
- **A disconnected device can hit its cap early.** It can spend only the
  rights it holds; spare rights on other devices reach it only through an
  exchange (safety over liveness). Rebalancing asks one peer at most every 5
  minutes per cap.
- **Advance minting needs the owner online after the 20th.** A device offline
  on the 1st holds next month's share only if the owner was on, and the share
  reached the device, between the 20th and the end of the month. Otherwise the
  device has no rights for the new month until it exchanges with someone who
  does.
- **Shares are equal**, not weighted by each device's usage; rebalancing moves
  rights to where they are spent, a request at a time.
- **A lower can leave the cap tighter than its target.** Devices burn on their
  own view; with stale views they can burn more than needed. That is safe; the
  owner raises the cap to recover.
- **A device that never cooperates keeps a lower from settling.** Rights held
  by a device that is gone, broken or malicious are counted until it burns them
  or is removed; `show` keeps reporting the pending decrease.
- **A cap whose owner device is removed is frozen**: its current rights stay
  usable, nobody adds rights again (not even an override), and next month has
  none. Ownership cannot move; create a new cap.
- **Removing a device that still holds rights** drops whatever it handed out
  after the remover's last exchange with it; run `tethra mesh cap reclaim`
  first.
- **Two caps created at once** on devices that cannot see each other: the one
  created first is the cap and the other is shown as superseded; it is never
  minted again but stays listed.
- **Windows:** the node has no control channel to ask; it treats anything
  listening on the gateway's configured port as a running gateway, so with
  enforcement on a transfer waits for the gateway's acknowledgement then.

## Credential sharing (Increment 11, ADR 0033)

- **No forward secrecy.** Shares are sealed to static per-device sealing keys.
  Anyone who later gets a recipient's vault and master password can open every
  share sealed to it that its store still holds.
- **A recipient keeps what it imported.** Revoking a share stops a device that
  has not imported it yet; it never removes a value from a vault, and it
  **does not revoke the credential at its provider**. To cut a device off,
  revoke its share first, then rotate the credential (`tethra rotation`, the
  Rotation view): after a rotation the sharing device offers a reseal of the
  new value to every device that held the old one, except devices whose share
  was revoked. For a removed or stolen device, rotate: removed devices are
  never offered a reseal.
- **Nothing is imported or resealed automatically.** Every share, import and
  reseal needs the master password. A device paired after a share to "all my
  devices", or a credential whose value changed, only gets a reseal *offer*
  on the sharing device; nothing is sent until the user reseals there.
- **An import by share id can be made ambiguous, or a share shadowed.** A
  misbehaving member can mint items that reuse another share's id (importing
  by that id is then refused as ambiguous), or mint its own item at another
  device's share key so the recipient sees that one instead. It can never
  deliver a value under another device's name (the bindings refuse it). The
  sharing device sees its share "replaced at the recipient" and a reseal
  offer; resealing (or revoking and resharing) puts its share back.
- **A share from a removed device cannot be imported,** even if it was made
  before the removal: the device may have been removed because it was lost
  or stolen. Ask an active device to share the credential.
- **A device revokes only the shares it made.** To end a share another
  device made, revoke it there (or remove that device).
- **A member can share a value under its own name.** The bindings stop a
  device planting a credential *attributed to another device*; they cannot
  stop one of your devices sharing a value of its own. The list and the import
  dialog always name the sharing device.
- **Size.** A shared value is at most 15 KiB, and the sealed box must fit
  16 KiB; a value that needs heavy JSON escaping can be refused below that.
- **Memory.** The value is held in zeroizing buffers while it is sealed or
  opened, but serde's scratch buffer for a JSON string that needs unescaping,
  and the vault's own copies while it re-encrypts, are not zeroized (the
  memory-inspection limitation of the root threat model).
- **The receiving device chooses the environment** of an imported
  credential (default development); the share does not carry it.
- **Desktop.** The share and import dialogs are covered by vitest and the
  backend paths by tests; a manual click-through
  (`docs/MANUAL_UI_TEST_PLAN.md` §D-S) is the owner's to run.
