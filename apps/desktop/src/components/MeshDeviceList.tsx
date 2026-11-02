// Devices view: every device this one knows, with its health, plus Pair a
// device and Remove (Increment 09). Removing a device needs BOTH steps, in
// order: an explicit confirmation, then the master password (re-verified in
// core). Creating an invite needs the master password too; the invite then
// lives in this component's state only while its dialog is open.

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { MeshDevice, MeshInvite } from "../types";
import { relativeTime } from "../useLiveRefresh";
import { formatTimestamp } from "../utils";
import { ConfirmDialog } from "./ConfirmDialog";
import { ReauthDialog } from "./ReauthDialog";
import { MeshPairDialog } from "./MeshPairDialog";
import { meshErrText, scrubbed, shortId } from "./MeshCommon";

function deviceLabel(d: MeshDevice): string {
  return `${d.name ?? "unnamed"} (${d.short_id || shortId(d.device_id)})`;
}

function Badges({ d }: { d: MeshDevice }) {
  return (
    <span style={{ display: "inline-flex", gap: "0.3rem", flexWrap: "wrap" }}>
      {d.is_self && <span className="badge ok">this device</span>}
      {d.stale && <span className="badge warn">stale</span>}
      {d.removed && <span className="badge bad">removed</span>}
      {d.fork_seq !== null && <span className="badge bad">forked</span>}
      {!d.active && !d.removed && <span className="badge warn">not admitted</span>}
    </span>
  );
}

function Lag({ d }: { d: MeshDevice }) {
  if (d.is_self || !d.lag) return <span className="muted">—</span>;
  const { lag } = d;
  return (
    <span title={`From the exchange at ${formatTimestamp(lag.at)}`}>
      lacks {lag.peer_behind_now} item(s) from this device; had {lag.peer_ahead} new
      {!lag.completed && " (that exchange ended early)"}
    </span>
  );
}

export function MeshDeviceList(props: { refreshKey: number; onChanged: () => void }) {
  const [devices, setDevices] = useState<MeshDevice[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pairing, setPairing] = useState(false);
  const [invite, setInvite] = useState<MeshInvite | null>(null);
  const [removal, setRemoval] = useState<{
    device: MeshDevice;
    step: "confirm" | "reauth";
  } | null>(null);

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
      const list = await api.meshDevices();
      if (!mounted.current || mine !== seq.current) return;
      setDevices(list);
      setError(null);
    } catch (e) {
      if (!mounted.current || mine !== seq.current) return;
      setError(meshErrText(e));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload, props.refreshKey]);

  const createInvite = async (password: string) => {
    try {
      const created = await api.meshInviteCreate(password, null);
      setNotice(null);
      setInvite(created);
    } catch (e) {
      // The reauth dialog shows this message (for example "the node is not
      // running"), never the typed password.
      throw scrubbed(e, [password]);
    }
  };

  const remove = async (password: string) => {
    if (!removal) return;
    const target = removal.device;
    try {
      const r = await api.meshDeviceRemove(password, target.device_id);
      setNotice(
        `Removed ${deviceLabel(target)}. The mesh access key rotated to epoch ` +
          `${r.access_key_epoch}; the other devices receive it in their next exchanges.`,
      );
    } catch (e) {
      throw scrubbed(e, [password]);
    }
    void reload();
    props.onChanged();
  };

  return (
    <section className="card stack" aria-labelledby="mesh-devices-title">
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
        <h2 id="mesh-devices-title" style={{ margin: 0 }}>
          Devices
        </h2>
        <span style={{ flex: 1 }} />
        <button type="button" onClick={() => setPairing(true)} disabled={invite !== null}>
          Pair a device
        </button>
      </div>
      <p className="muted">
        Pairing needs this device&apos;s node running (This device, above), because the new
        device connects to it.
      </p>
      {notice && <p className="notice">{notice}</p>}
      {error && (
        <p className="error" role="alert">
          Could not read the devices: {error}
        </p>
      )}
      {devices === null && !error && <p className="muted">Loading…</p>}
      {devices !== null && devices.length === 0 && <p className="muted">No devices yet.</p>}
      {devices !== null && devices.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Device</th>
                <th scope="col">State</th>
                <th scope="col">Last exchange</th>
                <th scope="col">Lag</th>
                <th scope="col">
                  <span className="muted">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.device_id}>
                  <td>{d.name ?? <span className="muted">unnamed</span>}</td>
                  <td>
                    <code>{d.short_id || shortId(d.device_id)}</code>
                  </td>
                  <td>
                    <Badges d={d} />
                  </td>
                  <td>
                    {d.is_self ? (
                      <span className="muted">—</span>
                    ) : (
                      <span title={formatTimestamp(d.last_exchange)}>
                        {relativeTime(d.last_exchange)}
                      </span>
                    )}
                  </td>
                  <td>
                    <Lag d={d} />
                  </td>
                  <td>
                    {!d.is_self && !d.removed && (
                      <button
                        type="button"
                        className="link danger"
                        aria-label={`Remove ${deviceLabel(d)}`}
                        onClick={() => setRemoval({ device: d, step: "confirm" })}
                      >
                        Remove
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {pairing && (
        <ReauthDialog
          title="Create a pairing invite"
          actionLabel="Create invite"
          body={
            "The invite lets one new device join this mesh. It is shown once and expires " +
            "after a few minutes."
          }
          onConfirm={createInvite}
          onClose={() => setPairing(false)}
        />
      )}
      {invite && <MeshPairDialog invite={invite} onClose={() => setInvite(null)} />}

      {removal?.step === "confirm" && (
        <ConfirmDialog
          title={`Remove ${deviceLabel(removal.device)}?`}
          body={
            "This device refuses it at once, and the other devices as they hear of it. Its " +
            "records up to now stay. It cannot rejoin under the same identity; to use it " +
            "again, it leaves and pairs again."
          }
          confirmLabel="Remove"
          danger
          onConfirm={() => setRemoval({ device: removal.device, step: "reauth" })}
          onCancel={() => setRemoval(null)}
        />
      )}
      {removal?.step === "reauth" && (
        <ReauthDialog
          title={`Remove ${deviceLabel(removal.device)}`}
          actionLabel="Remove device"
          onConfirm={remove}
          onClose={() => setRemoval(null)}
        />
      )}
    </section>
  );
}
