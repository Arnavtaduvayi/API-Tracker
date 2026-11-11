// Devices view: the addresses the node dials, where each came from and how
// dialling went, with add and remove (Increment 09; `tethra mesh peer`).

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { MeshPeer, MeshPeerSource } from "../types";
import { relativeTime } from "../useLiveRefresh";
import { formatTimestamp } from "../utils";
import { meshErrText, shortId } from "./MeshCommon";

const SOURCE_LABEL: Record<MeshPeerSource, string> = {
  manual: "manual",
  gossip: "gossip",
  mdns: "mDNS",
};

const SOURCE_HINT: Record<MeshPeerSource, string> = {
  manual: "You added it, or it is the invite address this device joined through.",
  gossip: "Another device publishes it as its listen address.",
  mdns: "Found by mDNS discovery on this network.",
};

function PeerDevice({ p }: { p: MeshPeer }) {
  if (!p.device_id) return <span className="muted">not yet known</span>;
  return (
    <span>
      {p.device_name ?? "unnamed"} <code>{shortId(p.device_id)}</code>
    </span>
  );
}

function PeerHealth({ p }: { p: MeshPeer }) {
  const parts: JSX.Element[] = [];
  if (p.unreachable_since) {
    parts.push(
      <div key="u">
        Unreachable since{" "}
        <span title={formatTimestamp(p.unreachable_since)}>
          {relativeTime(p.unreachable_since)}
        </span>
      </div>,
    );
  }
  if (p.backoff_until && Date.parse(p.backoff_until) > Date.now()) {
    parts.push(<div key="b">Retrying after {formatTimestamp(p.backoff_until)}</div>);
  }
  if (p.last_error) {
    parts.push(
      <div key="e" className="muted">
        Last error: {p.last_error}
      </div>,
    );
  }
  if (parts.length === 0) return <span className="muted">—</span>;
  return <>{parts}</>;
}

export function MeshPeers(props: { refreshKey: number; onChanged: () => void }) {
  const [peers, setPeers] = useState<MeshPeer[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [addr, setAddr] = useState("");
  const [busy, setBusy] = useState(false);

  const seq = useRef(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const reload = useCallback(async () => {
    const mine = ++seq.current;
    try {
      const list = await api.meshPeersList();
      if (!mounted.current || mine !== seq.current) return;
      setPeers(list);
      setError(null);
    } catch (e) {
      if (!mounted.current || mine !== seq.current) return;
      setError(meshErrText(e));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload, props.refreshKey]);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    const target = addr.trim();
    setBusy(true);
    setActionError(null);
    setNotice(null);
    try {
      const r = await api.meshPeerAdd(target);
      setNotice(
        r.added
          ? `Added ${r.addr}. A running node dials it at its next round.`
          : `${r.addr} is already a peer.`,
      );
      setAddr("");
      void reload();
      props.onChanged();
    } catch (err) {
      setActionError(meshErrText(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (target: string) => {
    setActionError(null);
    setNotice(null);
    try {
      const r = await api.meshPeerRemove(target);
      setNotice(
        !r.removed
          ? `${target} was not a peer.`
          : r.source === "manual"
            ? `Removed ${target}.`
            : `Removed ${target}; a device still publishing it brings it back at the next round.`,
      );
      void reload();
      props.onChanged();
    } catch (err) {
      setActionError(meshErrText(err));
    }
  };

  return (
    <section className="card stack" aria-labelledby="mesh-peers-title">
      <h2 id="mesh-peers-title">Peers</h2>
      <p className="muted">
        The addresses this device&apos;s node dials. A running node also learns the addresses
        the other devices publish, so you rarely need to add one by hand: a device that moved,
        or one across a VPN, where mDNS does not reach.
      </p>
      {notice && <p className="notice">{notice}</p>}
      {actionError && (
        <p className="error" role="alert">
          {actionError}
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          Could not read the peers: {error}
        </p>
      )}
      {peers === null && !error && <p className="muted">Loading…</p>}
      {peers !== null && peers.length === 0 && <p className="muted">No peer addresses yet.</p>}
      {peers !== null && peers.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th scope="col">Address</th>
                <th scope="col">Device</th>
                <th scope="col">Source</th>
                <th scope="col">Last success</th>
                <th scope="col">Failures</th>
                <th scope="col">Status</th>
                <th scope="col">
                  <span className="muted">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {peers.map((p) => (
                <tr key={p.addr}>
                  <td>
                    <code>{p.addr}</code>
                  </td>
                  <td>
                    <PeerDevice p={p} />
                  </td>
                  <td title={SOURCE_HINT[p.source]}>{SOURCE_LABEL[p.source] ?? p.source}</td>
                  <td title={formatTimestamp(p.last_success_at)}>
                    {relativeTime(p.last_success_at)}
                  </td>
                  <td>{p.failures}</td>
                  <td>
                    <PeerHealth p={p} />
                  </td>
                  <td>
                    <button
                      type="button"
                      className="link"
                      aria-label={`Remove peer ${p.addr}`}
                      onClick={() => void remove(p.addr)}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <form
        onSubmit={(e) => void add(e)}
        aria-label="Add a peer address"
        style={{ display: "flex", gap: "0.5rem", alignItems: "flex-end", flexWrap: "wrap" }}
      >
        <label className="field" style={{ flex: 1, minWidth: "14rem" }}>
          Add a peer address (HOST:PORT)
          <input
            value={addr}
            onChange={(e) => setAddr(e.target.value)}
            placeholder="100.64.1.2:7420 or desktop.tail1234.ts.net:7420"
            autoComplete="off"
            spellCheck={false}
            required
            className="mono"
          />
        </label>
        <button type="submit" disabled={busy || addr.trim() === ""}>
          {busy ? "Adding…" : "Add peer"}
        </button>
      </form>
    </section>
  );
}
