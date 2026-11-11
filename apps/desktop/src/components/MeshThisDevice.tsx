// Devices view: this device, its node and the node's local settings
// (Increment 09). The node runs inside the app while it is open and unlocked
// (DESIGN §D13). Settings that let other machines reach the node's listener
// (all interfaces, mDNS discovery, a non-loopback listen address) show a
// warning here and need the master password; core enforces that and answers
// `mesh_reauth_required` without it, so the UI asks and retries.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type {
  MeshNodeSettings,
  MeshNodeSettingsResult,
  MeshNodeStatus,
  MeshStatus,
} from "../types";
import { relativeTime } from "../useLiveRefresh";
import { formatTimestamp } from "../utils";
import { ReauthDialog } from "./ReauthDialog";
import { isLoopbackAddr, meshErrText, scrubbed, shortId } from "./MeshCommon";

type InMesh = MeshStatus & { initialized: true };

/** Whether these settings let other machines on the network reach the listener. */
export function exposesListener(s: MeshNodeSettings): boolean {
  return (
    s.all_interfaces ||
    s.discover ||
    s.listen.some((a) => a.trim() !== "" && !isLoopbackAddr(a))
  );
}

function AddrList({ addrs }: { addrs: string[] }) {
  if (addrs.length === 0) return <span className="muted">none</span>;
  return (
    <>
      {addrs.map((a, i) => (
        <span key={a}>
          {i > 0 && ", "}
          <code>{a}</code>
        </span>
      ))}
    </>
  );
}

function NodeFacts({ n }: { n: MeshNodeStatus }) {
  return (
    <ul>
      <li>
        Listening on: <AddrList addrs={n.listen} />
      </li>
      <li>
        Published to the other devices: <AddrList addrs={n.advertised} />
      </li>
      <li>
        Rounds: {n.rounds}; last round{" "}
        <span title={formatTimestamp(n.last_round_at)}>{relativeTime(n.last_round_at)}</span>
      </li>
      <li>Discovery (mDNS): {n.discovery ? "on" : "off"}</li>
      {n.last_publish_error && (
        <li className="error">Could not publish its addresses: {n.last_publish_error}</li>
      )}
      {n.last_hook_error && <li className="error">A round step failed: {n.last_hook_error}</li>}
    </ul>
  );
}

function NodeState({ status }: { status: InMesh }) {
  const node = status.node;
  let state: JSX.Element;
  if (node.running) {
    state = (
      <>
        <p>
          <span className="badge ok">running</span>{" "}
          {node.running.stopping ? "Stopping: finishing its exchanges." : "In this app."}
        </p>
        <NodeFacts n={node.running} />
      </>
    );
  } else if (node.stopping) {
    state = (
      <p>
        <span className="badge warn">stopping</span> Finishing its exchanges.
      </p>
    );
  } else if (node.external) {
    state = (
      <>
        <p>
          <span className="badge ok">running in another process</span> Another process (for
          example <code>tethra mesh serve</code>, pid {node.external.pid}) runs this
          device&apos;s node, so this app runs none until it stops.
        </p>
        <NodeFacts n={node.external} />
      </>
    );
  } else {
    state = (
      <p>
        <span className="badge">stopped</span> This device does not exchange with the others
        until a node runs.
      </p>
    );
  }
  return (
    <div>
      <h3>Mesh node</h3>
      {state}
      {node.last_error && (
        <p className="error" role="alert">
          The node could not start: {node.last_error}
        </p>
      )}
      {node.last_stop && !node.running && (
        <p className="muted">
          Last stopped {relativeTime(node.last_stop.at)}: {node.last_stop.description}
        </p>
      )}
    </div>
  );
}

function IdentityProblems({ status }: { status: InMesh }) {
  const items: string[] = [];
  if (status.marker !== "ok") {
    items.push(
      `This device's identity is not trusted (${status.marker_problem ?? `marker ${status.marker}`}). ` +
        "The node will not run and this device creates no mesh records. Leave the mesh and " +
        "pair it again.",
    );
  }
  if (status.self_forked) {
    items.push(
      "Another installation has used this device's identity (a fork was reported). Leave the " +
        "mesh and pair this device again.",
    );
  }
  if (status.rollback_hold !== null) {
    items.push(
      `A peer holds this device's records up to number ${status.rollback_hold}, past what ` +
        "this database has (it was restored from an older copy). Nothing is created here " +
        "until they come back, which the node's next exchange with that peer normally does.",
    );
  }
  if (items.length === 0) return null;
  return (
    <div className="error" role="alert">
      {items.map((t) => (
        <p key={t} style={{ margin: "0.25rem 0" }}>
          {t}
        </p>
      ))}
    </div>
  );
}

function Rename(props: { current: string; onChanged: () => void }) {
  const [draft, setDraft] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (draft === null) return;
    setBusy(true);
    setError(null);
    try {
      await api.meshDeviceRename(draft.trim());
      setDraft(null);
      setNotice("Renamed. The other devices see the new name after their next exchange.");
      props.onChanged();
    } catch (err) {
      setError(meshErrText(err));
    } finally {
      setBusy(false);
    }
  };

  if (draft === null) {
    return (
      <>
        <p>
          Name: <strong>{props.current}</strong>{" "}
          <button
            type="button"
            className="link"
            onClick={() => {
              setNotice(null);
              setError(null);
              setDraft(props.current);
            }}
          >
            Rename
          </button>
        </p>
        {notice && <p className="notice">{notice}</p>}
      </>
    );
  }
  return (
    <form className="stack" onSubmit={(e) => void save(e)} aria-label="Rename this device">
      <label className="field">
        New name for this device
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          required
          autoFocus
          autoComplete="off"
        />
        <span className="muted">Every device in the mesh sees this name.</span>
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div style={{ display: "flex", gap: "0.5rem" }}>
        <button type="submit" disabled={busy || draft.trim() === ""}>
          {busy ? "Saving…" : "Save name"}
        </button>
        <button type="button" onClick={() => setDraft(null)}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function outcomeText(r: MeshNodeSettingsResult): string {
  switch (r.outcome) {
    case "started":
      return "Saved. The mesh node started with these settings.";
    case "already_running":
      return "Saved. The mesh node is running with these settings.";
    case "off":
      return "Saved. The mesh node is off.";
    default:
      return "Saved.";
  }
}

function NodeSettingsEditor(props: { onChanged: () => void }) {
  const [draft, setDraft] = useState<MeshNodeSettings | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  /** Settings waiting for the master password (core said `mesh_reauth_required`). */
  const [pending, setPending] = useState<MeshNodeSettings | null>(null);

  const load = useCallback(async () => {
    try {
      setDraft(await api.meshNodeGetSettings());
      setLoadError(null);
    } catch (e) {
      setLoadError(meshErrText(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (!draft) {
    return loadError ? (
      <p className="error" role="alert">
        Could not read the node settings: {loadError}
      </p>
    ) : (
      <p className="muted">Loading the node settings…</p>
    );
  }

  const applied = (r: MeshNodeSettingsResult) => {
    setDraft(r.settings);
    setNotice(outcomeText(r));
    if (r.start_error) setError(`The node did not start: ${r.start_error}`);
    props.onChanged();
  };

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    const settings: MeshNodeSettings = {
      ...draft,
      listen: draft.listen.map((a) => a.trim()).filter((a) => a !== ""),
    };
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      applied(await api.meshNodeSetSettings(settings, null));
    } catch (err) {
      if (isApiError(err) && err.code === "mesh_reauth_required") {
        setPending(settings);
      } else {
        setError(meshErrText(err));
      }
    } finally {
      setBusy(false);
    }
  };

  const saveWithPassword = async (password: string) => {
    if (!pending) return;
    try {
      applied(await api.meshNodeSetSettings(pending, password));
    } catch (err) {
      throw scrubbed(err, [password]);
    }
  };

  const setListen = (i: number, value: string) =>
    setDraft({ ...draft, listen: draft.listen.map((a, j) => (j === i ? value : a)) });

  const exposed = exposesListener(draft);

  return (
    <>
      <form className="stack" onSubmit={(e) => void save(e)} aria-label="Mesh node settings">
        <h3>Node settings</h3>
        <p className="muted">
          These stay on this device. The node runs only while Tethra is open and unlocked; it
          stops when Tethra locks or quits.
        </p>
        <label>
          <input
            type="checkbox"
            checked={draft.run_while_open}
            onChange={(e) => setDraft({ ...draft, run_while_open: e.target.checked })}
          />{" "}
          Run mesh while Tethra is open
        </label>

        <fieldset style={{ border: 0, padding: 0, margin: "0.75rem 0" }}>
          <legend>Listen addresses</legend>
          <p className="muted">
            IP:PORT, such as <code>127.0.0.1:7420</code> for this computer only, or your LAN or
            VPN address such as <code>100.64.1.2:7420</code>. Port 0 picks a free port at each
            start.
          </p>
          {draft.listen.length === 0 && (
            <p className="muted">No listen address: the node cannot run until you add one.</p>
          )}
          {draft.listen.map((addr, i) => (
            <div key={i} style={{ display: "flex", gap: "0.5rem", alignItems: "flex-end" }}>
              <label className="field" style={{ flex: 1 }}>
                Listen address {i + 1}
                <input
                  value={addr}
                  onChange={(e) => setListen(i, e.target.value)}
                  placeholder="127.0.0.1:7420"
                  autoComplete="off"
                  spellCheck={false}
                  className="mono"
                />
              </label>
              <button
                type="button"
                aria-label={`Remove listen address ${i + 1}`}
                onClick={() =>
                  setDraft({ ...draft, listen: draft.listen.filter((_, j) => j !== i) })
                }
              >
                Remove
              </button>
            </div>
          ))}
          <div style={{ marginTop: "0.5rem" }}>
            <button
              type="button"
              onClick={() => setDraft({ ...draft, listen: [...draft.listen, ""] })}
            >
              Add listen address
            </button>
          </div>
        </fieldset>

        <label>
          <input
            type="checkbox"
            checked={draft.all_interfaces}
            onChange={(e) => setDraft({ ...draft, all_interfaces: e.target.checked })}
          />{" "}
          Allow all interfaces (0.0.0.0 / [::])
        </label>
        <br />
        <label>
          <input
            type="checkbox"
            checked={draft.discover}
            onChange={(e) => setDraft({ ...draft, discover: e.target.checked })}
          />{" "}
          Find devices on this network (mDNS)
        </label>

        {exposed && (
          <div className="warnbox" role="alert">
            <strong>
              Other machines on your network can reach this device&apos;s mesh listener.
            </strong>{" "}
            They still have to pass the handshake, which needs your mesh&apos;s keys, but the
            listener is exposed to them. Saving a change that opens it up asks for your master
            password.
          </div>
        )}

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {notice && <p className="notice">{notice}</p>}
        <div>
          <button type="submit" disabled={busy}>
            {busy ? "Saving…" : "Save node settings"}
          </button>
        </div>
      </form>
      {pending && (
        <ReauthDialog
          title="Allow network access"
          actionLabel="Save settings"
          body={
            "These settings let other machines on your network reach this device's mesh " +
            "listener (all interfaces, mDNS discovery, or a non-loopback address). They still " +
            "need your mesh's keys to get past the handshake."
          }
          onConfirm={saveWithPassword}
          onClose={() => setPending(null)}
        />
      )}
    </>
  );
}

export function MeshThisDevice(props: { status: InMesh; onChanged: () => void }) {
  const { status } = props;
  return (
    <section className="card stack" aria-labelledby="mesh-this-device-title">
      <h2 id="mesh-this-device-title">This device</h2>
      <IdentityProblems status={status} />
      <Rename current={status.device_name} onChanged={props.onChanged} />
      <p className="muted">
        Device <code>{shortId(status.device_id)}</code> in mesh{" "}
        <code>{status.mesh_id_short || shortId(status.mesh_id)}</code>, {status.roster_size}{" "}
        member(s).
      </p>
      <NodeState status={status} />
      <NodeSettingsEditor onChanged={props.onChanged} />
    </section>
  );
}
