# Tethra Mesh audit — findings index (2026-11-03)

Four independent auditors (A1 protocol and crypto `MP-`, A2 persistence and identity `MI-`, A3 caps and gateway `MC-`, A4 claims, UX and leakage `MD-`) reviewed `5ec8198..fb55b07`, read-only. 48 findings, deduplicated; no duplicates across auditors.
Verdicts: **41 confirmed** (each fixed failing-test-first, evidence in `evidence/<id>_baseline_fail.log.txt`), **7 accepted** residual risks (documented in `docs/mesh/KNOWN_LIMITATIONS.md`, with the reason below), 0 rejected.

| Id | Severity | Verdict | Finding | Decision |
|---|---|---|---|---|
| MP-1 | high | confirmed | A removed device's own roster.remove can raise its cutoff to u64::MAX and cancel its removal | Cutoff becomes the minimum over counting removes; a hostile low cutoff only shrinks what counts. |
| MP-2 | medium | confirmed | Peer-supplied dot hashes and unbounded ChainReply seqs yield fork evidence (even against oneself) | Fork evidence needs two verified signed items; an unsigned mismatch ends the session; ChainReply seqs bounded to (lo, hi]; never report a fork against oneself from a peer's word. |
| MP-3 | medium | confirmed | A device far behind never catches up while any repair is due (repair items push past max_staged) | The sender's plan budgets repair items inside max_staged, main path first. |
| MP-4 | medium | confirmed | A trickled handshake holds a session slot far past the handshake timeout | One deadline for the whole handshake. |
| MP-5 | medium | confirmed | noise_pub and seal_pub in roster.add are not checked for small-order points; a share to such a key is readable by anyone | Refuse small-order X25519 keys at parse (R10: invalid payload rejected). |
| MP-6 | medium | accepted | An LWW write at Hlc::MAX can never be overridden | LWW order is (hlc, origin), so any fixed HLC ceiling only moves where a compromised member can pin a register; a real fix needs causal supersession (each write naming the entry it replaces), a payload change for every LWW kind. Recovery today: replace the pinned object (a new cap, a new mesh project, or a new mesh). Documented in KNOWN_LIMITATIONS. |
| MP-7 | medium | confirmed | A member can add a device with a copied noise_pub and shadow the real device at the handshake | A static key matching several active devices resolves by the Hello's device id. |
| MP-8 | low | accepted | Equal-epoch access keys are grindable; the epoch ceiling counts removes of made-up ids | Defense-in-depth layer only: the roster check after the handshake refuses a removed device. Documented in KNOWN_LIMITATIONS. |
| MP-9 | low | confirmed | A RollbackNotice above the reporter's own Hello can stop a device minting | Ignore a notice whose held_seq exceeds the reporter's Hello vv for this device. |
| MP-10 | low | confirmed | Any member can revoke another device's share | A revoke counts only from the share's sharer or its recipient (PROTOCOL §5.6). |
| MP-11 | low | confirmed | Network failures during pairing burn invite attempts | Count only authenticated failures as attempts. |
| MP-12 | low | confirmed | inviter_verified is reported but not enforced | A join whose inviter key does not match fails. |
| MI-1 | high | confirmed | A failed multi-block mint batch leaves the marker >64 ahead of the durable VV: the identity is RolledBack for good | Reservations must survive a rolled-back minting transaction without looking like a rollback. |
| MI-2 | high | confirmed | mesh leave fails exactly when the identity is untrusted (marker missing/mismatched/rolled back, rollback hold) | Leave falls back to a local wipe when the self-removal cannot be minted; status shows an unreadable marker as a problem. |
| MI-3 | medium | confirmed | Restore commits mesh rows before the wipe in separate transactions | Backups carry no mesh_* rows and restore skips them (with MI-4). |
| MI-4 | low | confirmed | Backups contain wrapped mesh keys, access keys and invite psks | Exclude mesh_* tables from backups. |
| MI-5 | low | confirmed | Removal and access-key rotation are separate transactions; a failed rotation is never retried | A retry of a removal whose rotation is missing rotates. |
| MI-6 | low | accepted | Unix single-instance claim can race with a stale socket | Database-level safety holds (one writer per transaction, generation reloads); documented in KNOWN_LIMITATIONS. |
| MI-7 | low | accepted | Fork evidence noted in an earlier committed chunk is not reported if a later chunk fails | The fork is found again at the next Hello (chain comparison); documented. |
| MI-8 | low | confirmed | Deleting a shared credential leaves its shares live and unrevocable from this device | Deleting a credential with live outgoing shares is refused until they are revoked. |
| MI-9 | low | confirmed | Vault-connection mesh writes (init, join, rotation, wipe) lack fullfsync | Set fullfsync on those connections. |
| MC-1 | high | confirmed | A cold gate (p95 unknown after restart or at month start) admits unbounded concurrency | Serialize while no request cost is known. |
| MC-2 | high | confirmed | A burn awaiting the gateway's ack is not subtracted from the pending decrease: repeated reconciles burn again | Open burns in escrow count against the pending decrease (and reclaim asks). |
| MC-3 | medium | confirmed | Deleting local usage lowers cap.used and returns spent rights | cap.used never decreases within a month. |
| MC-4 | medium | confirmed | The caps simulator never runs the escrow fence and has no over-burn invariant | Add an over-burn invariant at quiescence; the fence-mode simulation is recorded as remaining work. |
| MC-5 | low | confirmed | avail is read before in_flight.fetch_add | Read avail after the reservation. |
| MC-6 | low | confirmed | A reclaim can take a holder's local override | A holder gives back at most its rights above its overrides. |
| MC-7 | low | confirmed | A charge for a vanished project leaves the gate's count without an incomplete flag | Flag accounting incomplete. |
| MC-8 | low | confirmed | One failed refresh installs an empty fail-open snapshot at once | Keep the last good snapshot until it is stale. |
| MC-9 | low | accepted | The gateway-running probe happens outside the write transaction | Window bounded by the 5 s poll and needs a gateway start in between; documented. |
| MC-10 | low | confirmed | Cap alert text ignores carried-over switches and the fail-open state | Alert text from the gate status. |
| MC-11 | low | accepted | The 403 drain holds a connection thread up to 5 s | Bounded (5 s, 64 MiB); documented in KNOWN_LIMITATIONS. |
| MC-12 | low | confirmed | The perf result is printed, not asserted, and measures neither charge nor a running poller | Honest wording in PERFORMANCE_RESULTS (measurement scope). |
| MD-1 | medium | confirmed | Docs and UI say overshoot is at most one request; concurrent admission and restart loss allow more | Qualify every such sentence (and MC-1, MC-5 shrink the gap). |
| MD-2 | medium | confirmed | MeshSetup says credential values do not replicate | Reword; update the test. |
| MD-3 | medium | confirmed | Removing a device does not warn that its imported credentials stay usable | Remove confirmations (CLI, desktop) say to rotate and suggest cap reclaim. |
| MD-4 | medium | confirmed | 'Rotate to cut a device off' plus all-device reseal resends the new value to that device | Guidance: revoke that device's share first (reseal never offers a revoked device). |
| MD-5 | medium | confirmed | Bind to a new project from Devices emits project_created analytics (MESH-SI-14) | Create the project without the analytics signal on that path; test with invoke mocked. |
| MD-6 | medium | confirmed | Absolute 'no double spending' claims | Qualify and point to limitations. |
| MD-7 | low | confirmed | Project panel says other devices see a shared project only after binding | Correct the text (name and usage are visible to every member). |
| MD-8 | low | confirmed | Lowering retention.usage_days (destructive, replicated) has no confirmation | CLI asks (or --yes) before lowering it. |
| MD-9 | low | confirmed | Stale status text in KNOWN_LIMITATIONS, mesh THREAT_MODEL, PRODUCT_SPEC, SI-8, SI-14 | Update. |
| MD-10 | low | confirmed | CLI help says caps are alerts only | Update help text. |
| MD-11 | low | confirmed | Unlocked-session row understates what can be done without the password | List it. |
| MD-12 | low | confirmed | What-replicates lists do not say share metadata is readable by every member | Say so. |
| MD-13 | low | confirmed | mesh status spacing; shares from removed devices counted as importable | Fix both. |
| MD-14 | low | confirmed | Inventory labels for revoke/list purge rows | Correct. |
| MD-15 | low | accepted | Invite copies in plain Strings for the response | The invite must reach the user once; short-lived (≤ 60 min, single use); documented. |

Status of each confirmed finding's fix: see the commits `fix(mesh): <id> …` and `FINAL_VERDICT.md`.
